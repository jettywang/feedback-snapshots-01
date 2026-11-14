import threading

import pytest

from noise.connection import Keypair, NoiseConnection
from noise.constants import (
    LENGTH_PREFIX_BYTES,
    TAG_LEN,
    MAX_TRANSPORT_FRAME_LEN,
    MAX_HANDSHAKE_FRAME_LEN,
)
from noise.exceptions import (
    NoiseFrameTooLargeError,
    NoiseInvalidMessage,
    NoiseStreamClosedError,
    NoiseTruncatedError,
)
from noise.stream import NoiseStream

PROTOCOL = b"Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s"
PSK = b"\x00" * 32
MESSAGES = [b"first business message", b"second one, a bit longer" * 4, b""]


def make_pair(fixed_ephemerals=False):
    initiator = NoiseConnection.from_name(PROTOCOL)
    initiator.set_psks(PSK)
    initiator.set_as_initiator()

    responder = NoiseConnection.from_name(PROTOCOL)
    responder.set_psks(PSK)
    responder.set_as_responder()

    if fixed_ephemerals:
        # Deterministic ephemerals make the whole handshake reproducible, so the
        # handshake hash can be compared across every fragmentation setting.
        initiator.set_keypair_from_private_bytes(Keypair.EPHEMERAL, b'\x11' * 32)
        responder.set_keypair_from_private_bytes(Keypair.EPHEMERAL, b'\x22' * 32)

    initiator.start_handshake()
    responder.start_handshake()
    return initiator, responder


class Pipe(object):
    """In-memory duplex byte stream with controllable read/write granularity.

    Writes land in one shared buffer; reads peel at most ``chunk`` bytes at a
    time so every possible fragmentation boundary (including splitting the
    4-byte length prefix) and arbitrary frame coalescing can be exercised.
    A read on an empty, open buffer blocks like a real socket; only an actual
    close produces the empty ``b''`` EOF marker.
    """

    def __init__(self, read_chunk=1, write_chunk=1):
        self.buffer = bytearray()
        self.read_chunk = read_chunk
        self.write_chunk = write_chunk
        self.closed = False
        self._cond = threading.Condition()

    def write(self, data):
        with self._cond:
            if self.closed:
                raise IOError('pipe closed')
            size = min(len(data), self.write_chunk)
            self.buffer.extend(data[:size])
            self._cond.notify_all()
            return size

    def read(self, size):
        with self._cond:
            while not self.buffer and not self.closed:
                self._cond.wait()
            if not self.buffer:
                return b''  # Genuine EOF after close.
            size = min(size, self.read_chunk, len(self.buffer))
            chunk = bytes(self.buffer[:size])
            del self.buffer[:size]
            return chunk

    def close(self):
        with self._cond:
            self.closed = True
            self._cond.notify_all()


class FailingWriter(object):
    """Sends ``surviving_bytes`` then raises on the next write attempt."""

    def __init__(self, surviving_bytes):
        self.surviving_bytes = surviving_bytes
        self.sent = bytearray()
        self.closed = False

    def write(self, data):
        if self.surviving_bytes <= 0:
            raise IOError('simulated write cancellation')
        size = min(len(data), self.surviving_bytes)
        self.sent.extend(data[:size])
        self.surviving_bytes -= size
        return size

    def read(self, size):
        return b''

    def close(self):
        self.closed = True


def drive_handshake(initiator, responder, pipe):
    initiator.write_handshake()
    responder.read_handshake()
    responder.write_handshake()
    initiator.read_handshake()
    assert initiator.handshake_finished and responder.handshake_finished


# Chunk sizes deliberately include 1 (byte-at-a-time), values around the prefix
# width, and sizes larger than any frame (full coalescing).
CHUNK_SIZES = [1, 2, 3, 4, 5, 7, 16, 32, 128, 4096]


class TestFragmentation(object):
    @pytest.mark.parametrize('write_chunk', CHUNK_SIZES)
    @pytest.mark.parametrize('read_chunk', CHUNK_SIZES)
    def test_every_fragmentation_combination(self, read_chunk, write_chunk):
        initiator, responder = make_pair()
        pipe = Pipe(read_chunk=read_chunk, write_chunk=write_chunk)
        client = NoiseStream(initiator, pipe)
        server = NoiseStream(responder, pipe)

        drive_handshake(client, server, pipe)

        reference_hash = initiator.get_handshake_hash()
        assert reference_hash == responder.get_handshake_hash()

        for message in MESSAGES:
            client.send(message)
            assert server.recv() == message

        # Reverse direction, same stream, same boundaries.
        for message in MESSAGES:
            server.send(message)
            assert client.recv() == message

        # Nothing left dangling in the pipe.
        assert not pipe.buffer

    def test_handshake_hash_stable_across_all_chunkings(self):
        hashes = set()
        for read_chunk in CHUNK_SIZES:
            for write_chunk in CHUNK_SIZES:
                initiator, responder = make_pair(fixed_ephemerals=True)
                pipe = Pipe(read_chunk=read_chunk, write_chunk=write_chunk)
                drive_handshake(NoiseStream(initiator, pipe), NoiseStream(responder, pipe), pipe)
                hashes.add(initiator.get_handshake_hash())
                hashes.add(responder.get_handshake_hash())
        assert len(hashes) == 1

    def test_multiple_frames_coalesced_into_single_buffer(self):
        initiator, responder = make_pair()
        pipe = Pipe(read_chunk=4096, write_chunk=4096)
        client = NoiseStream(initiator, pipe)
        server = NoiseStream(responder, pipe)
        drive_handshake(client, server, pipe)

        for message in MESSAGES:
            client.send(message)
        # All frames sit coalesced in the pipe; framing must still split them.
        delivered = [server.recv() for _ in MESSAGES]
        assert delivered == MESSAGES


class TestShortWrites(object):
    def test_short_writes_never_reencrypt(self):
        initiator, responder = make_pair()
        pipe = Pipe(read_chunk=3, write_chunk=2)
        client = NoiseStream(initiator, pipe)
        server = NoiseStream(responder, pipe)
        drive_handshake(client, server, pipe)

        plaintext = b'nonce must be consumed exactly once'
        nonce_before = initiator.noise_protocol.cipher_state_encrypt.n
        ciphertext = client.send(plaintext)
        nonce_after = initiator.noise_protocol.cipher_state_encrypt.n

        assert nonce_after == nonce_before + 1
        # Fragmented delivery still decrypts through the framing layer.
        assert server.recv() == plaintext
        assert not pipe.buffer

        # A deterministic re-run proves the adapter emitted exactly one
        # ciphertext: the same session state must yield byte-identical output,
        # and a byte-at-a-time replay of that single frame must decrypt.
        ref_initiator, ref_responder = make_pair(fixed_ephemerals=True)
        ref_pipe = Pipe(read_chunk=1, write_chunk=4096)
        ref_client = NoiseStream(ref_initiator, ref_pipe)
        ref_server = NoiseStream(ref_responder, ref_pipe)
        drive_handshake(ref_client, ref_server, ref_pipe)
        expected = ref_initiator.encrypt(plaintext)
        assert ref_initiator.noise_protocol.cipher_state_encrypt.n == 1

        frame = len(expected).to_bytes(LENGTH_PREFIX_BYTES, 'big') + expected
        ref_pipe.buffer.extend(frame)
        ref_pipe.closed = True
        assert ref_server.recv() == plaintext
        # One frame consumed exactly one inbound nonce, nothing buffered.
        assert ref_responder.noise_protocol.cipher_state_decrypt.n == 1
        assert not ref_pipe.buffer

    def test_encrypt_called_once_despite_byte_at_a_time_writes(self):
        initiator, responder = make_pair()
        pipe = Pipe(read_chunk=1, write_chunk=1)
        client = NoiseStream(initiator, pipe)
        server = NoiseStream(responder, pipe)
        drive_handshake(client, server, pipe)

        calls = []
        original_encrypt = initiator.encrypt

        def counting_encrypt(data):
            calls.append(data)
            return original_encrypt(data)

        initiator.encrypt = counting_encrypt
        try:
            client.send(b'painfully slow writer')
        finally:
            initiator.encrypt = original_encrypt

        assert calls == [b'painfully slow writer']
        assert server.recv() == b'painfully slow writer'

    def test_cancellation_after_partial_ciphertext_closes_session(self):
        initiator, responder = make_pair()
        pipe = Pipe(read_chunk=4096, write_chunk=4096)
        client = NoiseStream(initiator, pipe)
        server = NoiseStream(responder, pipe)
        drive_handshake(client, server, pipe)

        writer = FailingWriter(surviving_bytes=LENGTH_PREFIX_BYTES + 5)
        failing_client = NoiseStream(initiator, writer)
        nonce_before = initiator.noise_protocol.cipher_state_encrypt.n

        with pytest.raises(IOError):
            failing_client.send(b'frame that will not fully leave the process')

        # The nonce was consumed before the partial write...
        assert initiator.noise_protocol.cipher_state_encrypt.n == nonce_before + 1
        # ...partial bytes did leave...
        assert len(writer.sent) == LENGTH_PREFIX_BYTES + 5
        # ...and the session is dead instead of pretending nothing was sent.
        assert failing_client.closed
        assert writer.closed
        with pytest.raises(NoiseStreamClosedError):
            failing_client.send(b'anything further is refused')

    def test_cancellation_during_prefix_after_partial_prefix_closes_session(self):
        initiator, responder = make_pair()
        pipe = Pipe(read_chunk=4096, write_chunk=4096)
        client = NoiseStream(initiator, pipe)
        server = NoiseStream(responder, pipe)
        drive_handshake(client, server, pipe)

        # Only two of the four prefix bytes make it out before the cancellation.
        writer = FailingWriter(surviving_bytes=2)
        failing_client = NoiseStream(initiator, writer)
        nonce_before = initiator.noise_protocol.cipher_state_encrypt.n

        with pytest.raises(IOError):
            failing_client.send(b'prefix cut in half')

        assert initiator.noise_protocol.cipher_state_encrypt.n == nonce_before + 1
        assert len(writer.sent) == 2  # only the first half of the prefix
        assert failing_client.closed
        assert writer.closed

    def test_cancellation_before_any_byte_does_not_touch_stream(self):
        initiator, responder = make_pair()
        pipe = Pipe(read_chunk=4096, write_chunk=4096)
        client = NoiseStream(initiator, pipe)
        server = NoiseStream(responder, pipe)
        drive_handshake(client, server, pipe)

        writer = FailingWriter(surviving_bytes=0)
        failing_client = NoiseStream(initiator, writer)
        with pytest.raises(IOError):
            failing_client.send(b'nothing leaves')
        # No bytes were emitted; the underlying stream itself is not force-closed.
        assert not writer.sent
        assert not writer.closed


class TestOversizedPrefix(object):
    def test_transport_oversized_prefix_delivers_nothing(self):
        initiator, responder = make_pair()
        pipe = Pipe(read_chunk=4096, write_chunk=4096)
        client = NoiseStream(initiator, pipe)
        server = NoiseStream(responder, pipe)
        drive_handshake(client, server, pipe)

        evil_len = MAX_TRANSPORT_FRAME_LEN + 1
        pipe.buffer.extend(evil_len.to_bytes(LENGTH_PREFIX_BYTES, 'big'))
        pipe.buffer.extend(b'\x00' * 32)  # trailing bytes must never be consumed

        with pytest.raises(NoiseFrameTooLargeError):
            server.recv()
        assert server.closed
        # Reader stopped at the prefix; the following bytes remain untouched.
        assert bytes(pipe.buffer) == b'\x00' * 32

    def test_handshake_oversized_prefix_delivers_nothing(self):
        initiator, responder = make_pair()
        pipe = Pipe(read_chunk=4096, write_chunk=4096)
        server = NoiseStream(responder, pipe)

        evil_len = MAX_HANDSHAKE_FRAME_LEN + 1
        pipe.buffer.extend(evil_len.to_bytes(LENGTH_PREFIX_BYTES, 'big'))
        pipe.buffer.extend(b'untouched handshake payload')

        with pytest.raises(NoiseFrameTooLargeError):
            server.read_handshake()
        assert server.closed
        assert bytes(pipe.buffer) == b'untouched handshake payload'

    def test_undersized_declared_length_rejected_before_reading_body(self):
        _, responder = make_pair()
        pipe = Pipe(read_chunk=4096, write_chunk=4096)
        server = NoiseStream(responder, pipe)

        # NN first message is one ephemeral key (32 bytes); 31 cannot be valid.
        pipe.buffer.extend((31).to_bytes(LENGTH_PREFIX_BYTES, 'big'))
        pipe.buffer.extend(b'x' * 31)

        with pytest.raises(NoiseInvalidMessage):
            server.read_handshake()
        assert server.closed
        assert bytes(pipe.buffer) == b'x' * 31


class TestTruncation(object):
    def test_half_frame_eof_is_not_an_empty_message(self):
        initiator, responder = make_pair()
        pipe = Pipe(read_chunk=4096, write_chunk=4096)
        client = NoiseStream(initiator, pipe)
        server = NoiseStream(responder, pipe)
        drive_handshake(client, server, pipe)

        # Advertise 40 bytes but provide only 10, then signal EOF.
        pipe.buffer.extend((40).to_bytes(LENGTH_PREFIX_BYTES, 'big'))
        pipe.buffer.extend(b'\x00' * 10)
        pipe.closed = True

        with pytest.raises(NoiseTruncatedError):
            server.recv()
        assert server.closed

    def test_truncated_length_prefix_at_eof(self):
        _, responder = make_pair()
        pipe = Pipe(read_chunk=4096, write_chunk=4096)
        server = NoiseStream(responder, pipe)
        pipe.buffer.extend(b'\x00\x01')
        pipe.closed = True

        with pytest.raises(NoiseTruncatedError):
            server.read_handshake()
        assert server.closed

    def test_truncated_handshake_body_does_not_advance_handshake(self):
        initiator, responder = make_pair()
        pipe = Pipe(read_chunk=4096, write_chunk=4096)
        server = NoiseStream(responder, pipe)

        frame = initiator.write_message()
        # Advertise the real length, then cut the body in half and end the stream.
        pipe.buffer.extend(len(frame).to_bytes(LENGTH_PREFIX_BYTES, 'big'))
        pipe.buffer.extend(frame[:len(frame) // 2])
        pipe.closed = True

        with pytest.raises(NoiseTruncatedError):
            server.read_handshake()
        assert server.closed

    def test_clean_eof_is_distinct_from_half_frame(self):
        initiator, responder = make_pair()
        pipe = Pipe(read_chunk=4096, write_chunk=4096)
        client = NoiseStream(initiator, pipe)
        server = NoiseStream(responder, pipe)
        drive_handshake(client, server, pipe)

        pipe.closed = True
        # Nothing advertised: a real boundary EOF reads as empty, not an error.
        assert server.recv() == b''

    def test_corrupted_tag_tears_stream_down(self):
        initiator, responder = make_pair()
        pipe = Pipe(read_chunk=4096, write_chunk=4096)
        client = NoiseStream(initiator, pipe)
        server = NoiseStream(responder, pipe)
        drive_handshake(client, server, pipe)

        ciphertext = client.send(b'authenticate me')
        # Flip the final byte, which is part of the Poly1305 tag.
        pipe.buffer[-1] ^= 0xFF
        with pytest.raises(NoiseInvalidMessage):
            server.recv()
        assert server.closed
        assert len(ciphertext) == len(b'authenticate me') + TAG_LEN
