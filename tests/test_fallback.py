import os

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization

from noise.backends.default.keypairs import KeyPair25519
from noise.connection import Keypair, NoiseConnection
from noise.exceptions import NoiseHandshakeError

PROTOCOL_NAME = b'Noise_IK_25519_AESGCM_SHA256'


def _static_keypair():
    return KeyPair25519.from_private_bytes(os.urandom(32))


def _private_bytes(keypair):
    return keypair.private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())


def _ik_initiator(static_keypair, remote_static_public):
    connection = NoiseConnection.from_name(PROTOCOL_NAME)
    connection.set_keypair_from_private_bytes(Keypair.STATIC, _private_bytes(static_keypair))
    connection.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, remote_static_public)
    connection.set_as_initiator()
    connection.start_handshake()
    return connection


def _ik_responder(static_keypair):
    connection = NoiseConnection.from_name(PROTOCOL_NAME)
    connection.set_keypair_from_private_bytes(Keypair.STATIC, _private_bytes(static_keypair))
    connection.set_as_responder()
    connection.start_handshake()
    return connection


class TestFallback(object):
    def test_ik_fallback_after_static_rotation(self):
        # Client cached the server's old static key, server rotated to a new one
        client_static = _static_keypair()
        server_old_static = _static_keypair()
        server_new_static = _static_keypair()

        client = _ik_initiator(client_static, server_old_static.public_bytes)
        server = _ik_responder(server_new_static)

        # First IK message cannot be decrypted by the responder - it was encrypted to the old static key
        message1 = client.write_message(b'client-hello')
        with pytest.raises(InvalidTag):
            server.read_message(message1)

        # The application authorises the fallback on the responder side
        server_fallback = server.begin_fallback()
        assert server_fallback.protocol_name == b'Noise_XXfallback_25519_AESGCM_SHA256'
        server_fallback.start_handshake()
        fallback_message1 = server_fallback.write_message()

        # The initiator cannot parse it as the second IK message either
        with pytest.raises(InvalidTag):
            client.read_message(fallback_message1)

        # The application authorises the fallback on the initiator side
        client_fallback = client.begin_fallback()
        client_fallback.start_handshake()
        payload = client_fallback.read_message(fallback_message1)
        assert payload == b''
        fallback_message2 = client_fallback.write_message(b'client-hello')
        assert server_fallback.read_message(fallback_message2) == b'client-hello'

        assert client_fallback.handshake_finished
        assert server_fallback.handshake_finished

        # Both parties arrived at the same transcript and transport keys
        handshake_hash = client_fallback.get_handshake_hash()
        assert handshake_hash is not None
        assert handshake_hash == server_fallback.get_handshake_hash()

        # The new static identities are the freshly learned ones
        assert client_fallback.get_remote_static_key() == server_new_static.public_bytes
        assert server_fallback.get_remote_static_key() == client_static.public_bytes

        # Transport is gated on explicit application confirmation of the new static identity
        with pytest.raises(NoiseHandshakeError):
            client_fallback.encrypt(b'ping')
        with pytest.raises(NoiseHandshakeError):
            server_fallback.decrypt(b'')

        client_fallback.confirm_remote_static()
        server_fallback.confirm_remote_static()

        ciphertext = client_fallback.encrypt(b'ping')
        assert server_fallback.decrypt(ciphertext) == b'ping'
        ciphertext = server_fallback.encrypt(b'pong')
        assert client_fallback.decrypt(ciphertext) == b'pong'

        # The superseded IK connections cannot be used anymore
        with pytest.raises(NoiseHandshakeError, match='superseded'):
            client.write_message()
        with pytest.raises(NoiseHandshakeError, match='superseded'):
            server.read_message(message1)

    def test_fallback_rejects_tampered_first_message(self):
        client_static = _static_keypair()
        server_static = _static_keypair()

        client = _ik_initiator(client_static, server_static.public_bytes)
        server = _ik_responder(server_static)

        # Attacker replaces the ephemeral inside the first IK message
        message1 = bytearray(client.write_message(b'client-hello'))
        message1[10] ^= 0x01
        with pytest.raises(InvalidTag):
            server.read_message(bytes(message1))

        # Responder side fallback is built on the attacker's ephemeral...
        server_fallback = server.begin_fallback()
        server_fallback.start_handshake()
        fallback_message1 = server_fallback.write_message()

        # ...but the honest initiator's transcript no longer matches, so the fallback handshake fails
        client_fallback = client.begin_fallback()
        client_fallback.start_handshake()
        with pytest.raises(InvalidTag):
            client_fallback.read_message(fallback_message1)

        # No transport keys are established and nothing can be sent
        assert not client_fallback.handshake_finished
        assert not server_fallback.handshake_finished
        with pytest.raises(NoiseHandshakeError):
            client_fallback.encrypt(b'ping')

    def test_begin_fallback_rejected_on_inapplicable_states(self):
        client_static = _static_keypair()
        server_static = _static_keypair()

        # Handshake not started yet
        connection = NoiseConnection.from_name(PROTOCOL_NAME)
        with pytest.raises(NoiseHandshakeError):
            connection.begin_fallback()

        # Initiator that has not sent the first message yet
        initiator = _ik_initiator(client_static, server_static.public_bytes)
        with pytest.raises(NoiseHandshakeError):
            initiator.begin_fallback()

        # Responder that has not received anything
        responder = _ik_responder(server_static)
        with pytest.raises(NoiseHandshakeError):
            responder.begin_fallback()

        # Failed fallback attempts have no side effects - a normal IK handshake still completes
        message1 = initiator.write_message(b'hello')
        assert responder.read_message(message1) == b'hello'
        message2 = responder.write_message()
        initiator.read_message(message2)
        assert initiator.handshake_finished and responder.handshake_finished
        assert responder.decrypt(initiator.encrypt(b'still works')) == b'still works'

        # Finished handshakes cannot fall back
        with pytest.raises(NoiseHandshakeError):
            initiator.begin_fallback()
        with pytest.raises(NoiseHandshakeError):
            responder.begin_fallback()

        # Patterns without a defined fallback cannot fall back
        nn = NoiseConnection.from_name(b'Noise_NN_25519_AESGCM_SHA256')
        nn.set_as_initiator()
        nn.start_handshake()
        nn.write_message()
        with pytest.raises(NoiseHandshakeError):
            nn.begin_fallback()

        # Fallback can only be triggered once
        client = _ik_initiator(client_static, _static_keypair().public_bytes)
        rotated_server = _ik_responder(_static_keypair())
        message1 = client.write_message()
        with pytest.raises(InvalidTag):
            rotated_server.read_message(message1)
        rotated_server.begin_fallback()
        with pytest.raises(NoiseHandshakeError):
            rotated_server.begin_fallback()

    def test_remote_static_rejection_blocks_transport(self):
        client_static = _static_keypair()
        server_static = _static_keypair()

        client = _ik_initiator(client_static, _static_keypair().public_bytes)
        server = _ik_responder(server_static)

        message1 = client.write_message()
        with pytest.raises(InvalidTag):
            server.read_message(message1)

        server_fallback = server.begin_fallback()
        server_fallback.start_handshake()
        fallback_message1 = server_fallback.write_message()

        client_fallback = client.begin_fallback()
        client_fallback.start_handshake()
        client_fallback.read_message(fallback_message1)
        server_fallback.read_message(client_fallback.write_message())
        assert client_fallback.handshake_finished and server_fallback.handshake_finished

        # The application rejects the new static identity - transport stays closed permanently
        client_fallback.reject_remote_static()
        with pytest.raises(NoiseHandshakeError):
            client_fallback.encrypt(b'ping')
        with pytest.raises(NoiseHandshakeError):
            client_fallback.decrypt(b'')
        with pytest.raises(NoiseHandshakeError):
            client_fallback.confirm_remote_static()
        with pytest.raises(NoiseHandshakeError):
            client_fallback.encrypt(b'ping')

        # Confirmation APIs are only meaningful on fallback connections
        plain = NoiseConnection.from_name(PROTOCOL_NAME)
        with pytest.raises(NoiseHandshakeError):
            plain.confirm_remote_static()
        with pytest.raises(NoiseHandshakeError):
            plain.reject_remote_static()
