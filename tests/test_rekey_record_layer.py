import struct

import pytest

from noise.connection import NoiseConnection
from examples.rekey.rekey_record_layer import (
    ConnectionClosed, MemoryEndpoint, RekeyRecordLayer, SendBlocked, Tracer,
    T_APP, T_REKEY,
)


def make_pair():
    a_io, b_io = MemoryEndpoint('A-io'), MemoryEndpoint('B-io')
    a_io.connect(b_io)
    b_io.connect(a_io)
    a_noise = NoiseConnection.from_name(b'Noise_XX_25519_ChaChaPoly_BLAKE2s')
    b_noise = NoiseConnection.from_name(b'Noise_XX_25519_ChaChaPoly_BLAKE2s')
    a_noise.set_as_initiator()
    b_noise.set_as_responder()
    a_noise.noise_protocol.keypairs['s'] = a_noise.noise_protocol.dh_fn.generate_keypair()
    b_noise.noise_protocol.keypairs['s'] = b_noise.noise_protocol.dh_fn.generate_keypair()
    a_noise.start_handshake()
    b_noise.start_handshake()
    b_io.inbuf += a_noise.write_message()
    b_noise.read_message(bytes(b_io.inbuf)); b_io.inbuf.clear()
    a_io.inbuf += b_noise.write_message()
    a_noise.read_message(bytes(a_io.inbuf)); a_io.inbuf.clear()
    b_io.inbuf += a_noise.write_message()
    b_noise.read_message(bytes(b_io.inbuf)); b_io.inbuf.clear()
    tracer = Tracer()
    tracer.log = lambda *a, **k: None
    tracer.note = lambda *a, **k: None
    return (RekeyRecordLayer(a_noise, a_io, 'A', tracer),
            RekeyRecordLayer(b_noise, b_io, 'B', tracer), a_io, b_io)


def send_cs(layer):
    return layer.noise.noise_protocol.cipher_state_encrypt


def recv_cs(layer):
    return layer.noise.noise_protocol.cipher_state_decrypt


class TestRekeyRecordLayer:
    def test_rekey_does_not_reset_nonce_and_changes_key(self):
        A, B, _, _ = make_pair()
        A.send_app(b'one')
        A.send_app(b'two')
        assert B.recv() == ('app', b'one')
        assert B.recv() == ('app', b'two')
        old_key = send_cs(A).k
        nonce_before = send_cs(A).n
        A.initiate_rekey()
        assert send_cs(A).n == nonce_before + 1  # REKEY record consumed a nonce
        assert send_cs(A).k != old_key
        A.send_app(b'three')
        assert B.recv() == ('rekey', 1)
        assert recv_cs(B).n == nonce_before + 1  # receiver nonce also continues
        assert B.recv() == ('app', b'three')

    def test_concurrent_bidirectional_rekey(self):
        A, B, _, _ = make_pair()
        A.initiate_rekey()
        B.initiate_rekey()
        A.send_app(b'a-gen1')
        B.send_app(b'b-gen1')
        assert B.recv() == ('rekey', 1)
        assert A.recv() == ('rekey', 1)
        assert B.recv() == ('app', b'a-gen1')
        assert A.recv() == ('app', b'b-gen1')
        assert A.send_gen == B.recv_gen == 1
        assert B.send_gen == A.recv_gen == 1

    def test_partial_control_write_defers_state_transition(self):
        A, B, a_io, _ = make_pair()
        old_key = send_cs(A).k
        a_io.fail_after = 5
        A.initiate_rekey()
        assert A.pending is not None
        assert A.send_gen == 0 and send_cs(A).k == old_key  # not advanced
        assert B.recv() is None  # incomplete frame is inert
        with pytest.raises(SendBlocked):
            A.send_app(b'x')
        nonce_after_blocked = send_cs(A).n  # blocked send must not burn a nonce
        assert nonce_after_blocked == 1
        assert A.flush() is True
        assert A.send_gen == 1 and send_cs(A).k != old_key
        assert B.recv() == ('rekey', 1)

    def test_duplicate_rekey_ignored(self):
        A, B, _, _ = make_pair()
        A.initiate_rekey()
        assert B.recv() == ('rekey', 1)
        # buggy peer re-sends REKEY(gen=1) under the now-current key
        A._enqueue(A._frame(T_REKEY, struct.pack('!Q', 1)), is_rekey=False)
        assert B.recv() == ('dup', 1)
        assert B.recv_gen == 1
        A.send_app(b'still alive')
        assert B.recv() == ('app', b'still alive')

    def test_out_of_window_rekey_closes(self):
        A, B, _, _ = make_pair()
        A._enqueue(A._frame(T_REKEY, struct.pack('!Q', 7)), is_rekey=False)
        with pytest.raises(ConnectionClosed):
            B.recv()
        with pytest.raises(ConnectionClosed):
            B.send_app(b'x')

    def test_old_generation_record_closes_without_key_search(self):
        A, B, a_io, b_io = make_pair()
        A.send_app(b'gen0 record')
        assert B.recv() == ('app', b'gen0 record')
        captured = a_io.sent_log[-1]
        A.initiate_rekey()
        assert B.recv() == ('rekey', 1)
        b_io.inbuf += captured  # replayed old-generation record
        with pytest.raises(ConnectionClosed):
            B.recv()

    def test_app_payload_cannot_impersonate_control_record(self):
        A, B, _, _ = make_pair()
        # payload bytes identical to a REKEY body arrive as plain app data
        A.send_app(bytes([T_REKEY]) + struct.pack('!Q', 1))
        kind, body = B.recv()
        assert kind == 'app'
        assert body == bytes([T_REKEY]) + struct.pack('!Q', 1)
        assert B.recv_gen == 0  # no rekey happened

    def test_unknown_record_type_closes(self):
        A, B, _, _ = make_pair()
        A._enqueue(A._frame(0x7F, b''), is_rekey=False)
        with pytest.raises(ConnectionClosed):
            B.recv()
