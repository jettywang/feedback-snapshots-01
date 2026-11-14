import pytest

from examples.channel_binding.channel_binding import (
    HmacLoginIssuer,
    HmacLoginVerifier,
    LoginAdmissionError,
    LoginBindingError,
    LoginProof,
    LoginProofError,
    LoginProxy,
    LoginStateError,
    NoiseLoginChannel,
    ROLE_INITIATOR,
    ROLE_RESPONDER,
    establish_kk_channels,
    generate_issuer_key,
    generate_static_keypair,
)

SERVICE = 'demo-service'
USER = 'alice'
OTHER_SERVICE = 'other-service'


def _issuer_and_verifier():
    key = generate_issuer_key()
    return HmacLoginIssuer(key), HmacLoginVerifier(key), key


def _server():
    return generate_static_keypair()


def _channel(server, service=SERVICE):
    client = generate_static_keypair()
    return establish_kk_channels(client[0], client[1], server[0], server[1], service)


def _transplant(proof, target_client, target_server, verifier):
    return target_server.accept_login(target_client.seal_login(proof), verifier)


def _login(client, server, proxy, verifier, user=USER):
    proof = proxy.proof_for(client)
    server.accept_login(client.seal_login(proof), verifier)
    client.accept_login_accepted(server.seal_login_accepted(), expected_user=user)


def test_two_simultaneous_channels_reject_cross_forwarding():
    issuer, verifier, _ = _issuer_and_verifier()
    server = _server()
    client_a, server_a = _channel(server)
    client_b, server_b = _channel(server)
    proxy_a, proxy_b = LoginProxy(issuer, USER), LoginProxy(issuer, USER)

    assert client_a.handshake_hash != client_b.handshake_hash
    proof_a = proxy_a.proof_for(client_a)
    proof_b = proxy_b.proof_for(client_b)

    with pytest.raises(LoginProofError, match='different handshake'):
        _transplant(proof_a, client_b, server_b, verifier)
    assert server_b.authenticated_user is None
    assert server_b.failed_attempts == 1

    with pytest.raises(LoginProofError, match='different handshake'):
        _transplant(proof_b, client_a, server_a, verifier)
    assert server_a.authenticated_user is None
    assert server_a.failed_attempts == 1

    _login(client_a, server_a, proxy_a, verifier)
    _login(client_b, server_b, proxy_b, verifier)
    assert server_a.authenticated_user == server_b.authenticated_user == USER

    with pytest.raises(LoginStateError, match='already authenticated'):
        server_a.accept_login(client_a.seal_login(proof_a), verifier)
    assert server_a.open(client_a.seal(b'protected-op')) == b'protected-op'
    assert server_b.open(client_b.seal(b'protected-op')) == b'protected-op'


def test_reconnect_does_not_reuse_old_proof():
    issuer, verifier, _ = _issuer_and_verifier()
    server = _server()
    client = generate_static_keypair()
    client_a, server_a = establish_kk_channels(*client, *server, SERVICE)
    proof_a = LoginProxy(issuer, USER).proof_for(client_a)

    client_b, server_b = establish_kk_channels(*client, *server, SERVICE)
    assert client_a.handshake_hash != client_b.handshake_hash
    with pytest.raises(LoginProofError, match='different handshake'):
        _transplant(proof_a, client_b, server_b, verifier)
    assert server_b.authenticated_user is None


def test_same_peers_different_service_rejects_proof():
    issuer, verifier, _ = _issuer_and_verifier()
    server = _server()
    client_a, server_a = _channel(server, SERVICE)
    client_b, server_b = _channel(server, OTHER_SERVICE)
    proof_a = LoginProxy(issuer, USER).proof_for(client_a)

    with pytest.raises(LoginProofError, match='different service'):
        _transplant(proof_a, client_b, server_b, verifier)
    assert server_b.authenticated_user is None


def test_service_and_role_are_bound_by_verifier():
    issuer, verifier, _ = _issuer_and_verifier()
    server = _server()
    client, channel = _channel(server)
    hash_value = channel.handshake_hash

    proof = issuer.issue(SERVICE, USER, hash_value, ROLE_INITIATOR)
    with pytest.raises(LoginProofError, match='different service'):
        verifier.verify(proof, OTHER_SERVICE, ROLE_INITIATOR, hash_value)

    reverse_role_proof = issuer.issue(SERVICE, USER, hash_value, ROLE_RESPONDER)
    with pytest.raises(LoginProofError, match='different role'):
        verifier.verify(reverse_role_proof, SERVICE, ROLE_INITIATOR, hash_value)


def test_proof_is_usable_only_after_handshake_and_admission():
    issuer, verifier, _ = _issuer_and_verifier()
    server = _server()
    client, server_channel = establish_kk_channels(*generate_static_keypair(), *server, SERVICE, admit=False)
    proxy = LoginProxy(issuer, USER)

    assert client.handshake_finished and server_channel.handshake_finished
    with pytest.raises(LoginStateError, match='admission'):
        proxy.proof_for(client)
    with pytest.raises(LoginStateError, match='admission'):
        server_channel.accept_login(b'\x00' * 64, verifier)
    assert server_channel.authenticated_user is None
    assert server_channel.failed_attempts == 0


def test_handshake_hash_is_not_an_access_token():
    issuer, verifier, _ = _issuer_and_verifier()
    server = _server()
    client_a, _ = _channel(server)
    client_b, server_b = _channel(server)
    proof_a = LoginProxy(issuer, USER).proof_for(client_a)

    # Knowing channel B's public handshake hash and a valid tag for A is
    # not enough: relabelling the proof to B's hash invalidates the tag.
    relabelled = LoginProof(
        SERVICE, USER, ROLE_INITIATOR, client_b.handshake_hash, proof_a.tag
    )
    with pytest.raises(LoginProofError, match='invalid proof tag'):
        verifier.verify(relabelled, SERVICE, ROLE_INITIATOR, client_b.handshake_hash)
    assert server_b.authenticated_user is None

    # A proof minted with an unrelated key is likewise rejected.
    attacker_issuer = HmacLoginIssuer(b'\xAA' * 32)
    forged = attacker_issuer.issue(SERVICE, USER, client_b.handshake_hash, ROLE_INITIATOR)
    with pytest.raises(LoginProofError, match='invalid proof tag'):
        verifier.verify(forged, SERVICE, ROLE_INITIATOR, client_b.handshake_hash)


def test_issuer_key_is_separate_from_noise_keys():
    issuer, verifier, signing_key = _issuer_and_verifier()
    server = _server()
    client = generate_static_keypair()
    client_channel, server_channel = establish_kk_channels(*client, *server, SERVICE)

    assert signing_key != client[0]
    assert signing_key != server[0]
    assert signing_key != client_channel.connection.noise_protocol.cipher_state_encrypt.k
    assert signing_key != server_channel.connection.noise_protocol.cipher_state_encrypt.k
    assert client[0] != client_channel.connection.noise_protocol.cipher_state_encrypt.k

    with pytest.raises(LoginProofError, match='invalid proof tag'):
        forged = HmacLoginIssuer(b'\x01' * 32).issue(
            SERVICE, USER, client_channel.handshake_hash, ROLE_INITIATOR
        )
        verifier.verify(forged, SERVICE, ROLE_INITIATOR, client_channel.handshake_hash)


def test_wrong_peer_static_key_fails_admission():
    issuer, verifier, _ = _issuer_and_verifier()
    server = _server()
    client = generate_static_keypair()
    client_channel, server_channel = establish_kk_channels(*client, *server, SERVICE)

    impostor = generate_static_keypair()
    wrong_policy = NoiseLoginChannel(
        server_channel.connection,
        SERVICE,
        ROLE_RESPONDER,
        expected_remote_static=impostor[1],
    )
    with pytest.raises(LoginAdmissionError, match='admission failed'):
        wrong_policy.confirm_admission()
    with pytest.raises(LoginStateError, match='admission'):
        LoginProxy(issuer, USER).proof_for(wrong_policy)
    assert wrong_policy.authenticated_user is None
    assert not wrong_policy.is_authenticated


def test_login_cannot_be_started_before_handshake():
    from noise.connection import Keypair, NoiseConnection

    issuer, verifier, _ = _issuer_and_verifier()
    server = _server()
    connection = NoiseConnection.from_name(b'Noise_KK_25519_ChaChaPoly_SHA256')
    connection.set_as_responder()
    connection.set_keypair_from_private_bytes(Keypair.STATIC, server[0])
    connection.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, generate_static_keypair()[1])
    connection.start_handshake()
    channel = NoiseLoginChannel(connection, SERVICE, ROLE_RESPONDER)

    assert not channel.handshake_finished
    with pytest.raises(LoginStateError, match='handshake'):
        channel.confirm_admission()
    with pytest.raises(LoginStateError, match='handshake'):
        LoginProxy(issuer, USER).proof_for(channel)
    with pytest.raises(LoginStateError, match='handshake'):
        channel.accept_login(b'not a proof', verifier)
    assert channel.authenticated_user is None
    assert channel.failed_attempts == 0


def test_failed_login_leaves_no_authenticated_state():
    issuer, verifier, _ = _issuer_and_verifier()
    server = _server()
    client, server_channel = _channel(server)

    assert not server_channel.is_authenticated
    with pytest.raises(LoginStateError, match='not authenticated'):
        server_channel.open(b'\x00' * 16)
    with pytest.raises(LoginStateError, match='not authenticated'):
        server_channel.seal(b'data')

    wrong_proof = issuer.issue(OTHER_SERVICE, USER, server_channel.handshake_hash, ROLE_INITIATOR)
    with pytest.raises(LoginProofError):
        server_channel.accept_login(client.seal_login(wrong_proof), verifier)
    assert server_channel.authenticated_user is None
    assert not server_channel.is_authenticated
    assert server_channel.failed_attempts == 1


def test_tampered_or_plaintext_proof_is_rejected():
    issuer, verifier, _ = _issuer_and_verifier()
    server = _server()
    client, server_channel = _channel(server)
    proof = LoginProxy(issuer, USER).proof_for(client)
    ciphertext = client.seal_login(proof)
    tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])

    with pytest.raises(Exception):
        server_channel.accept_login(tampered, verifier)
    assert server_channel.authenticated_user is None
    with pytest.raises(Exception):
        server_channel.accept_login(proof.to_bytes(), verifier)
    assert server_channel.authenticated_user is None


@pytest.mark.parametrize('bad_key', [b'', b'\x00' * 31])
def test_issuer_and_verifier_reject_short_keys(bad_key):
    with pytest.raises(LoginBindingError, match='at least 32 bytes'):
        HmacLoginIssuer(bad_key)
    with pytest.raises(LoginBindingError, match='at least 32 bytes'):
        HmacLoginVerifier(bad_key)
