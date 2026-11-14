"""Thin byte-stream adapter on top of the message-oriented NoiseConnection.

The :class:`~noise.connection.NoiseConnection` API exchanges whole, self
contained Noise messages. Real transports (sockets, pipes, ...) are byte
streams with no notion of message boundaries: a single Noise message may arrive
in arbitrarily many fragments and several messages may be coalesced into one
read. This module adds an explicit length-prefix framing layer so that any
file-like object (``read``/``write``) or socket (``recv``/``send``) can carry a
Noise session.

Wire format of every frame, in both the handshake and the transport phase::

    +-------------------------+----------------------------------+
    | 4-byte big-endian length | payload of exactly that many bytes|
    +-------------------------+----------------------------------+

Security properties enforced here:

* The advertised length is constrained against what the current phase can
  actually produce (handshake tokens / AEAD tag included) *before* the payload
  is read, so an oversized prefix cannot make the reader buffer unbounded data.
* A frame whose stream ends before all advertised bytes arrive raises
  :class:`~noise.exceptions.NoiseTruncatedError`; a half frame at EOF is never
  delivered as an empty message or fed to the cipher.
* Short writes keep sending the *same* ciphertext buffer. The underlying
  ``encrypt`` / ``write_message`` is invoked exactly once per frame, so a slow
  writer never burns an extra nonce.
* If the writer is cancelled (raises) after part of a frame has left the
  process the session is torn down: the nonce was already consumed and the peer
  may have received partial bytes, so the frame cannot be treated as unsent.
"""

from noise.connection import NoiseConnection
from noise.constants import (
    LENGTH_PREFIX_BYTES,
    TAG_LEN,
    MAX_HANDSHAKE_FRAME_LEN,
    MAX_TRANSPORT_FRAME_LEN,
)
from noise.exceptions import (
    NoiseFrameTooLargeError,
    NoiseInvalidMessage,
    NoiseStreamClosedError,
    NoiseTruncatedError,
)

# Pattern tokens that contribute raw or encrypted bytes to a handshake message.
_TOKEN_E = 'e'
_TOKEN_S = 's'


class NoiseStream(object):
    """Length-prefixed framing around a :class:`NoiseConnection`.

    :param connection: a configured, possibly handshake-initialized NoiseConnection
    :param stream: byte transport exposing either ``read(size)``/``write(data)``
        (file-like) or ``recv(size)``/``send(data)`` (socket-like); a write may
        perform a short write, the adapter retries with the remainder of the
        same buffer.
    """

    def __init__(self, connection: NoiseConnection, stream):
        if not isinstance(connection, NoiseConnection):
            raise TypeError('connection must be a NoiseConnection instance')
        # Accept both file-like objects (read/write) and sockets (recv/send).
        self._read_fn = getattr(stream, 'read', None) or getattr(stream, 'recv', None)
        self._write_fn = getattr(stream, 'write', None) or getattr(stream, 'send', None)
        if self._read_fn is None or self._write_fn is None:
            raise TypeError('stream must expose read/recv and write/send')
        self.connection = connection
        self._stream = stream
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def handshake_finished(self) -> bool:
        return self.connection.handshake_finished

    def get_handshake_hash(self) -> bytes:
        return self.connection.get_handshake_hash()

    # ------------------------------------------------------------------ read

    def _read_exact(self, size):
        """Read exactly ``size`` bytes, distinguishing EOF from truncation."""
        chunks = []
        remaining = size
        while remaining:
            chunk = self._read_fn(remaining)
            if chunk is None:
                # Some non-blocking adapters signal "no data yet" instead of blocking.
                continue
            if not chunk:
                if not chunks and remaining == size:
                    return b''  # Clean EOF, nothing consumed for this read.
                raise NoiseTruncatedError(
                    'Stream ended with {} of {} expected bytes missing'.format(remaining, size)
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        return b''.join(chunks)

    def _declared_bounds(self):
        """Return (minimum, maximum) legal frame length for the current phase."""
        if not self.connection.handshake_finished:
            return self._handshake_bounds(), MAX_HANDSHAKE_FRAME_LEN
        return TAG_LEN, MAX_TRANSPORT_FRAME_LEN

    def _handshake_bounds(self):
        """Smallest structurally legal handshake message for the next pattern."""
        protocol = self.connection.noise_protocol
        message_pattern = protocol.handshake_state.message_patterns[0]
        dhlen = protocol.dh_fn.dhlen
        has_key = protocol.cipher_state_handshake.has_key()
        minimum = TAG_LEN if has_key else 0  # tag protecting the payload
        for token in message_pattern:
            if token == _TOKEN_E:
                minimum += dhlen
            elif token == _TOKEN_S:
                minimum += dhlen + TAG_LEN if has_key else dhlen
        return minimum

    def _read_frame(self):
        """Read one complete, length-validated frame.

        Returns ``None`` on a clean EOF at a frame boundary; raises and tears
        the stream down on any framing violation so unverified bytes are never
        handed to the upper layer.
        """
        if self._closed:
            raise NoiseStreamClosedError('NoiseStream is closed')

        try:
            prefix = self._read_exact(LENGTH_PREFIX_BYTES)
        except NoiseTruncatedError:
            self._fail()
            raise
        if not prefix:
            return None  # Clean EOF between frames.

        declared = int.from_bytes(prefix, byteorder='big', signed=False)
        minimum, maximum = self._declared_bounds()
        if declared > maximum:
            self._fail()
            raise NoiseFrameTooLargeError(
                'Frame advertises {} bytes, phase allows at most {}'.format(declared, maximum)
            )
        if declared < minimum:
            self._fail()
            raise NoiseInvalidMessage(
                'Frame advertises {} bytes, phase requires at least {}'.format(declared, minimum)
            )

        try:
            frame = self._read_exact(declared)
        except NoiseTruncatedError:
            self._fail()
            raise
        return frame

    def read_handshake(self) -> bytearray:
        """Read a framed handshake message and feed it to NoiseConnection."""
        frame = self._read_frame()
        if frame is None:
            raise NoiseTruncatedError('EOF reached while a handshake message was expected')
        try:
            return self.connection.read_message(frame)
        except Exception:
            self._fail()
            raise

    def recv(self) -> bytes:
        """Read one authenticated transport message and return its plaintext."""
        frame = self._read_frame()
        if frame is None:
            return b''  # Clean EOF at a frame boundary.
        try:
            return self.connection.decrypt(frame)
        except Exception:
            # Authentication failure (or any cipher error): the stream state is
            # no longer trustworthy, tear the session down.
            self._fail()
            raise

    # ----------------------------------------------------------------- write

    def _write_all(self, data):
        """Send all of ``data``, retrying short writes with the same buffer."""
        view = memoryview(data)
        total = len(view)
        sent = 0
        try:
            while sent < total:
                written = self._write_fn(view[sent:])
                if written is None:
                    continue
                if written <= 0:
                    raise IOError('underlying write made no progress')
                sent += written
        except BaseException:
            if sent > 0:
                # Some ciphertext already left the process. The nonce behind
                # this frame was consumed; retrying would desync the session,
                # so it must be closed rather than silently rewritten.
                self._fail()
            raise

    def _write_frame(self, frame):
        if self._closed:
            raise NoiseStreamClosedError('NoiseStream is closed')
        _, maximum = self._declared_bounds()
        if len(frame) > maximum:
            self._fail()
            raise NoiseFrameTooLargeError(
                'Refusing frame of {} bytes; phase max is {}'.format(len(frame), maximum)
            )
        prefix = len(frame).to_bytes(LENGTH_PREFIX_BYTES, byteorder='big', signed=False)
        self._write_all(prefix)
        self._write_all(frame)

    def write_handshake(self, payload: bytes = b'') -> bytearray:
        """Generate, frame and send a handshake message (exactly once)."""
        if self._closed:
            raise NoiseStreamClosedError('NoiseStream is closed')
        frame = self.connection.write_message(payload)
        self._write_frame(frame)
        return frame

    def send(self, data: bytes) -> bytes:
        """Encrypt ``data`` once and send the resulting frame, retrying writes."""
        if self._closed:
            raise NoiseStreamClosedError('NoiseStream is closed')
        # Encrypt exactly once: short writes must not produce a fresh nonce.
        ciphertext = self.connection.encrypt(data)
        self._write_frame(ciphertext)
        return ciphertext

    # ----------------------------------------------------------------- close

    def _fail(self):
        self._closed = True
        self.close()

    def close(self):
        """Mark the session dead and release the underlying stream."""
        if self._stream is not None and hasattr(self._stream, 'close'):
            try:
                self._stream.close()
            except Exception:
                pass
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
