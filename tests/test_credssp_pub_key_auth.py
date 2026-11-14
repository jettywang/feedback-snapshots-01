import dataclasses
import hashlib
import socket
import types
import typing

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import spnego
import spnego._credssp as credssp
from spnego._credssp_structures import TSRequest, TSPasswordCreds
from spnego._ntlm import NTLMProxy
from spnego.exceptions import BadBindingsError, InvalidTokenError, NegotiateOptions
from spnego.tls import CredSSPTLSContext, default_tls_context, generate_tls_certificate

# A fixed DER-like public key and nonce for the independent binding vectors.
PUBLIC_KEY = b"\x30\x01\x02\x03" + bytes(range(4, 32))
CLIENT_NONCE = bytes(range(32))

LEGACY_CLIENT_BINDING = PUBLIC_KEY
LEGACY_SERVER_BINDING = bytes([PUBLIC_KEY[0] + 1]) + PUBLIC_KEY[1:]

CLIENT_BINDING_V5 = bytes.fromhex("6d1c3ca6c3f2ecb49bae23ece5c01af98c3b5bbc2a112d80e8a2c2415807ccb0")
SERVER_BINDING_V5 = bytes.fromhex("7fdc6ec0d5c44a92af8d46219d67d6a4ee189875f8a77fb3647ed00fc6946cc8")


def pub_key_auth(pub_key: bytes, usage: str, nonce: typing.Optional[bytes] = None) -> bytes:
    """Builds the expected public key auth independently of the implementation."""
    if nonce is not None:
        assert len(nonce) == 32
        direction = b"Client-To-Server" if usage == "initiate" else b"Server-To-Client"
        return hashlib.sha256(b"CredSSP " + direction + b" Binding Hash\x00" + nonce + pub_key).digest()

    if usage == "accept":
        return bytes([(pub_key[0] + 1) % 256]) + pub_key[1:]

    return pub_key


def tls_public_key(cert_der: bytes) -> bytes:
    cert = x509.load_der_x509_certificate(cert_der)
    return cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)


def acceptor_tls_context(tmp_path) -> typing.Tuple[CredSSPTLSContext, bytes]:
    cert_pem, key_pem, public_key = generate_tls_certificate()

    cert_path = tmp_path / "credssp.pem"
    with open(cert_path, mode="wb") as fd:
        fd.write(cert_pem)
        fd.write(key_pem)

    context = default_tls_context(usage="accept")
    context.context.load_cert_chain(str(cert_path))
    context.public_key = public_key
    return context, public_key


@dataclasses.dataclass
class ObservedTSRequest:
    usage: str
    stage: str
    request: TSRequest


def record_raw_wraps(context: NTLMProxy) -> typing.List[bytes]:
    """Records the unwrapped values passed into the NTLM context."""
    wraps = []
    original_wrap = context.wrap

    def wrapper(self, data, encrypt=True, qop=None):
        wraps.append(bytes(data))
        return original_wrap(data, encrypt, qop)

    context.wrap = types.MethodType(wrapper, context)
    return wraps


def record_ts_requests(context: credssp.CredSSPProxy) -> typing.List[ObservedTSRequest]:
    """Records the actual outbound TSRequest order for a CredSSP endpoint."""
    requests = []
    original_wrap = context.wrap

    def wrapper(self, data, encrypt=True, qop=None):
        requests.append(ObservedTSRequest(self.usage, self.get_extra_info("auth_stage"), TSRequest.unpack(data)))
        return original_wrap(data, encrypt, qop)

    context.wrap = types.MethodType(wrapper, context)
    return requests


RequestOrder = typing.Tuple[str, str, int, bool, typing.Optional[int], bool, bool]


def request_order(requests: typing.List[ObservedTSRequest]) -> typing.List[RequestOrder]:
    return [
        (
            observed.usage,
            observed.stage,
            observed.request.version,
            bool(observed.request.nego_tokens),
            None if observed.request.client_nonce is None else len(observed.request.client_nonce),
            bool(observed.request.pub_key_auth),
            bool(observed.request.auth_info),
        )
        for observed in requests
    ]


def make_contexts(
    ntlm_cred,
    tmp_path,
    monkeypatch,
    version: int,
    *,
    client_min: int = 2,
    server_min: int = 2,
) -> typing.Tuple[
    credssp.CredSSPProxy,
    credssp.CredSSPProxy,
    typing.List[bytes],
    typing.List[bytes],
    NTLMProxy,
    NTLMProxy,
    bytes,
]:
    monkeypatch.setattr(credssp, "_CREDSSP_VERSION", version)

    acceptor, acceptor_key = acceptor_tls_context(tmp_path)
    initiator = default_tls_context(usage="initiate")

    kwargs = {
        "hostname": socket.gethostname(),
        "protocol": "negotiate",
        "options": NegotiateOptions.use_ntlm,
    }
    client_ntlm = spnego.client(ntlm_cred[0], ntlm_cred[1], **kwargs)
    server_ntlm = spnego.server(**kwargs)
    assert isinstance(client_ntlm, NTLMProxy)
    assert isinstance(server_ntlm, NTLMProxy)

    client = credssp.CredSSPProxy(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        protocol="credssp",
        options=NegotiateOptions.use_ntlm,
        credssp_tls_context=initiator,
        credssp_negotiate_context=client_ntlm,
        credssp_min_protocol=client_min,
    )
    server = credssp.CredSSPProxy(
        None,
        None,
        hostname=socket.gethostname(),
        protocol="credssp",
        usage="accept",
        options=NegotiateOptions.use_ntlm,
        credssp_tls_context=acceptor,
        credssp_negotiate_context=server_ntlm,
        credssp_min_protocol=server_min,
    )
    return (
        client,
        server,
        record_raw_wraps(client_ntlm),
        record_raw_wraps(server_ntlm),
        client_ntlm,
        server_ntlm,
        acceptor_key,
    )


def finish_tls(client: credssp.CredSSPProxy, server: credssp.CredSSPProxy) -> typing.Optional[bytes]:
    """Runs the in-memory TLS handshake and returns the server's auth response."""
    server_token = None
    while client.get_extra_info("auth_stage") == "TLS Handshake":
        client_token = client.step(server_token)
        assert client_token is not None
        assert not client.complete
        assert not server.complete

        server_token = server.step(client_token)
        assert server_token is not None
        assert not client.complete
        assert not server.complete

    assert client.get_extra_info("ssl_object").cipher() is not None
    assert server.get_extra_info("ssl_object").cipher() is not None
    return server_token


def assert_no_auth_info(client_requests: typing.List[ObservedTSRequest], server: credssp.CredSSPProxy) -> None:
    assert not [observed for observed in client_requests if observed.request.auth_info]
    assert server.get_extra_info("client_credential") is None


@pytest.mark.parametrize(
    "usage, nonce, expected",
    [
        ("initiate", None, LEGACY_CLIENT_BINDING),
        ("accept", None, LEGACY_SERVER_BINDING),
        ("initiate", CLIENT_NONCE, CLIENT_BINDING_V5),
        ("accept", CLIENT_NONCE, SERVER_BINDING_V5),
    ],
)
def test_pub_key_auth_vectors(usage, nonce, expected):
    assert credssp._get_pub_key_auth(PUBLIC_KEY, usage, nonce=nonce) == expected


@pytest.mark.parametrize("version", [2, 5, 6])
def test_pub_key_auth_exchange(version, ntlm_cred, tmp_path, monkeypatch):
    client, server, client_raw_wraps, server_raw_wraps, client_ntlm, server_ntlm, acceptor_key = make_contexts(
        ntlm_cred, tmp_path, monkeypatch, version
    )
    client_requests = record_ts_requests(client)
    server_requests = record_ts_requests(server)

    server_token = finish_tls(client, server)
    pub_key_request = client.step(server_token)
    assert pub_key_request is not None
    server_pub_key_response = server.step(pub_key_request)
    assert server_pub_key_response is not None
    credential_response = client.step(server_pub_key_response)
    assert credential_response is not None
    assert server.step(credential_response) is None

    assert client.complete
    assert server.complete
    assert client.get_extra_info("protocol_version") == version
    assert server.get_extra_info("protocol_version") == version

    assert request_order(client_requests) == [
        ("initiate", "Authentication 1", version, True, None, False, False),
        ("initiate", "Public key exchange", version, True, 32 if version > 4 else None, True, False),
        ("initiate", "Credential exchange", version, False, None, False, True),
    ]
    assert request_order(server_requests) == [
        ("accept", "Authentication 1", version, True, None, False, False),
        ("accept", "Public key exchange", version, False, None, True, False),
    ]

    peer_key = tls_public_key(client.get_extra_info("ssl_object").getpeercert(True))
    assert peer_key == acceptor_key

    pub_key_observation = client_requests[1]
    nonce = pub_key_observation.request.client_nonce
    if version > 4:
        assert nonce is not None
        assert len(nonce) == 32
    else:
        assert nonce is None

    expected_client = pub_key_auth(peer_key, "initiate", nonce)
    expected_server = pub_key_auth(peer_key, "accept", nonce)
    assert expected_client != expected_server
    assert client_raw_wraps[0] == expected_client
    assert server_raw_wraps[0] == expected_server

    credential = server.get_extra_info("client_credential")
    domain, username = ntlm_cred[0].split("\\", 1)
    assert isinstance(credential, TSPasswordCreds)
    assert credential.domain_name == domain
    assert credential.username == username
    assert credential.password == ntlm_cred[1]


@pytest.mark.parametrize("fault", ["reflected", "wrong_tls_key", "missing_nonce", "missing_pub_key_auth"])
def test_pub_key_auth_rejects_bad_acceptor_binding(fault, ntlm_cred, tmp_path, monkeypatch):
    client, server, _, _, client_ntlm, server_ntlm, acceptor_key = make_contexts(
        ntlm_cred, tmp_path, monkeypatch, 6
    )
    client_requests = record_ts_requests(client)

    server_token = finish_tls(client, server)
    client_pub_key_token = client.step(server_token)
    assert client_pub_key_token is not None

    client_request = TSRequest.unpack(server.unwrap(client_pub_key_token).data)
    assert client_request.client_nonce is not None
    assert len(client_request.client_nonce) == 32
    assert client_request.pub_key_auth is not None

    assert server_ntlm.step(client_request.nego_tokens[0].nego_token) is None
    assert server_ntlm.complete
    assert client_ntlm.complete

    expected_client = pub_key_auth(acceptor_key, "initiate", client_request.client_nonce)
    assert server_ntlm.unwrap(client_request.pub_key_auth).data == expected_client

    if fault == "reflected":
        response_binding = pub_key_auth(acceptor_key, "initiate", client_request.client_nonce)

    elif fault == "wrong_tls_key":
        _, _, other_key = generate_tls_certificate()
        assert other_key != acceptor_key
        response_binding = pub_key_auth(other_key, "accept", client_request.client_nonce)

    elif fault == "missing_nonce":
        response_binding = pub_key_auth(acceptor_key, "accept", None)

    else:
        response_binding = None

    response = TSRequest(6, pub_key_auth=server_ntlm.wrap(response_binding).data if response_binding else None)
    response_token = server.wrap(response.pack()).data

    assert client.get_extra_info("ssl_object").cipher() is not None
    assert server.get_extra_info("ssl_object").cipher() is not None
    expected_error = BadBindingsError if response_binding else InvalidTokenError
    expected_message = (
        "Public key verification failed, potential man in the middle attack"
        if response_binding
        else "Acceptor did not response with pubKeyAuth info"
    )
    with pytest.raises(expected_error, match=expected_message):
        client.step(response_token)

    assert client_ntlm.complete
    assert server_ntlm.complete
    assert not client.complete
    assert client.get_extra_info("auth_stage") == "Public key exchange"
    assert request_order(client_requests) == [
        ("initiate", "Authentication 1", 6, True, None, False, False),
        ("initiate", "Public key exchange", 6, True, 32, True, False),
    ]
    assert_no_auth_info(client_requests, server)


def test_pub_key_auth_min_version_blocks_auth_info(ntlm_cred, tmp_path, monkeypatch):
    client, server, _, _, client_ntlm, _, _ = make_contexts(
        ntlm_cred, tmp_path, monkeypatch, 4, client_min=5
    )
    client_requests = record_ts_requests(client)

    server_token = finish_tls(client, server)
    with pytest.raises(
        InvalidTokenError, match="The peer protocol version was 4 and did not meet the minimum requirements of 5"
    ):
        client.step(server_token)

    assert client_ntlm.complete
    assert client.get_extra_info("ssl_object").cipher() is not None
    assert client.get_extra_info("protocol_version") == 4
    assert not client.complete
    assert request_order(client_requests) == [("initiate", "Authentication 1", 4, True, None, False, False)]
    assert_no_auth_info(client_requests, server)
