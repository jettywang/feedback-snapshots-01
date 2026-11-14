"""
Minimal bidirectional rekey record layer on top of an authenticated Noise channel.

Built on the existing primitives:
  - noise.connection.NoiseConnection          (authenticated channel, Noise_XX here)
  - NoiseConnection.rekey_outbound_cipher()   (Noise spec rekey: k = ENCRYPT(k, 2^64-1, '', 0*32)[:32])
  - NoiseConnection.rekey_inbound_cipher()    (rekey NEVER resets the nonce counter n)

Record format on the wire:
    u16be length || AEAD( type(1) || body )

The type byte lives *inside* the AEAD plaintext, so a control record cannot be
forged or replayed by anyone without the current key, and application payloads
can never be mistaken for control records: the application-facing API only ever
emits T_APP records; T_REKEY records are only produced by initiate_rekey().

Deterministic rules implemented here:

 1. Boundary. A T_REKEY(new_gen) record is the LAST record encrypted under the
    old key of its direction. The very next record (nonce+1, nonce is NOT reset)
    is the first record under the new key. Directions are fully independent:
    each direction has its own CipherState, generation and rekey boundary.

 2. Send failure. A record is encrypted exactly once (consuming exactly one
    nonce). If the transport write fails halfway, the layer keeps
    (frame_bytes, offset) and retries the *identical* remaining bytes on
    flush(); it never re-encrypts (that would burn a second nonce and desync
    the receiver). The sender applies rekey_outbound_cipher() and bumps its
    generation ONLY after the REKEY frame has been fully flushed. While any
    frame is pending, new sends are rejected with SendBlocked.

 3. Simultaneous rekey. Both peers may rekey their own send direction at the
    same time; the two directions do not interact, so no tie-break is needed.
    Within one direction only the sender of that direction can initiate a
    rekey, so there is exactly one initiator per direction.

 4. Duplicate control records. REKEY carries the new generation number.
    Receiver: gen == recv_gen+1 -> apply rekey_inbound_cipher(), recv_gen += 1.
    gen == recv_gen -> duplicate, ignore. Anything else -> close.

 5. Old-generation records. The receiver keeps NO historical keys and never
    tries them. A late/replayed record from a previous generation (or any
    forgery) simply fails AEAD authentication -> the connection is closed.

Close conditions (all deterministic, all final):
  - AEAD authentication failure on any record (old-generation, replay, forgery)
  - unknown record type
  - REKEY generation outside {recv_gen, recv_gen+1}
  - nonce exhaustion (NoiseMaxNonceError from CipherState; rekey does NOT
    reset the nonce, so the limit applies to the whole channel lifetime)
After closing, every send/recv raises ConnectionClosed.
"""

import hashlib
import struct

from noise.connection import NoiseConnection, Keypair
from noise.exceptions import NoiseMaxNonceError

T_APP = 0x00
T_REKEY = 0x01
TYPE_NAMES = {T_APP: 'APP', T_REKEY: 'REKEY'}


class TransportIOError(IOError):
    def __init__(self, msg, written=0):
        super().__init__(msg)
        self.written = written  # bytes already delivered before the failure


class SendBlocked(Exception):
    """A previous frame is not fully flushed; retry flush() before sending."""


class ConnectionClosed(Exception):
    pass


class MemoryEndpoint:
    """One end of an in-memory duplex byte stream.

    Fault-injection knobs used by the demo:
      fail_after  - deliver only this many bytes of the next write, then raise
      sent_log    - tap recording every delivered chunk (used to replay an
                    old-generation record later)
    """

    def __init__(self, name):
        self.name = name
        self.peer = None
        self.inbuf = bytearray()
        self.sent_log = []
        self.fail_after = None

    def connect(self, peer):
        self.peer = peer

    def write(self, data):
        if self.fail_after is not None:
            n = min(self.fail_after, len(data))
            self.fail_after = None
            self._deliver(data[:n])
            raise TransportIOError(
                '{}: transport failed after {}/{} bytes'.format(self.name, n, len(data)),
                written=n)
        self._deliver(data)
        return len(data)

    def _deliver(self, chunk):
        self.sent_log.append(bytes(chunk))
        self.peer.inbuf += chunk

    def read(self, n):
        chunk = bytes(self.inbuf[:n])
        del self.inbuf[:n]
        return chunk


class Tracer:
    """Collects and prints the actual encrypt/decrypt trajectory."""

    def __init__(self):
        self.events = []

    def log(self, kind, who, gen, nonce, keyfp, rtype, detail=''):
        self.events.append((kind, who, gen, nonce, keyfp, rtype, detail))
        print('  {:<4} {:<5} gen={} nonce={:<3} key={} type={:<6} {}'.format(
            kind, who, gen, nonce, keyfp, TYPE_NAMES.get(rtype, '?'), detail))

    def note(self, text):
        self.events.append(('note', '', '', '', '', '', text))
        print('  *** {}'.format(text))


def keyfp(cipher_state):
    return hashlib.sha256(cipher_state.k).hexdigest()[:10]


class RekeyRecordLayer:
    def __init__(self, noise, transport, name, tracer):
        self.noise = noise            # NoiseConnection, handshake finished
        self.io = transport           # MemoryEndpoint
        self.name = name
        self.tracer = tracer
        self.send_gen = 0
        self.recv_gen = 0
        self.pending = None           # [frame_bytes, offset, is_rekey]
        self.rbuf = bytearray()
        self.closed = None

    # -- internal helpers ---------------------------------------------------

    def _send_cs(self):
        return self.noise.noise_protocol.cipher_state_encrypt

    def _recv_cs(self):
        return self.noise.noise_protocol.cipher_state_decrypt

    def _check_open(self):
        if self.closed is not None:
            raise ConnectionClosed('{}: {}'.format(self.name, self.closed))

    def _close(self, reason):
        self.closed = reason
        self.tracer.note('{} CLOSED: {}'.format(self.name, reason))

    def _frame(self, rtype, body):
        cs = self._send_cs()
        nonce, fp = cs.n, keyfp(cs)
        try:
            ct = self.noise.encrypt(bytes([rtype]) + body)
        except NoiseMaxNonceError:
            self._close('nonce exhausted; rekey does not reset the nonce, channel lifetime over')
            raise ConnectionClosed(self.closed)
        self.tracer.log('enc', self.name, self.send_gen, nonce, fp, rtype,
                        'body={!r}'.format(body[:32]))
        return struct.pack('!H', len(ct)) + ct

    # -- sending ------------------------------------------------------------

    def _enqueue(self, frame, is_rekey):
        self.pending = [frame, 0, is_rekey]
        self.flush()

    def _check_can_send(self):
        self._check_open()
        if self.pending is not None:
            # Checked BEFORE encrypting: a rejected send must not burn a nonce.
            raise SendBlocked('{}: previous frame not fully flushed'.format(self.name))

    def send_app(self, data):
        """Application API: can only ever produce T_APP records."""
        self._check_can_send()
        self._enqueue(self._frame(T_APP, data), is_rekey=False)

    def initiate_rekey(self):
        """Encrypt REKEY under the CURRENT key; apply the rekey only after the
        frame is fully flushed (see flush())."""
        self._check_can_send()
        self._enqueue(self._frame(T_REKEY, struct.pack('!Q', self.send_gen + 1)),
                      is_rekey=True)

    def flush(self):
        """Drive the pending frame out. Retries identical bytes after a partial
        write; never re-encrypts. Returns True when nothing is pending."""
        if self.pending is None:
            return True
        frame, off, is_rekey = self.pending
        try:
            while off < len(frame):
                off += self.io.write(frame[off:])
        except TransportIOError as e:
            off += e.written
            self.pending = [frame, off, is_rekey]
            self.tracer.note('{}: partial write ({}/{} bytes) - state NOT advanced, '
                             'will retry identical bytes'.format(self.name, off, len(frame)))
            return False
        self.pending = None
        if is_rekey:
            # Boundary: the REKEY record just sent was the LAST record under
            # the old key. Nonce keeps counting; only the key changes.
            old_fp = keyfp(self._send_cs())
            self.noise.rekey_outbound_cipher()
            self.send_gen += 1
            self.tracer.note('{}: send boundary crossed -> gen={} (key {} -> {}, '
                             'nonce continues at {})'.format(
                                 self.name, self.send_gen, old_fp,
                                 keyfp(self._send_cs()), self._send_cs().n))
        return True

    # -- receiving ----------------------------------------------------------

    def recv(self):
        """Returns ('app', data) | ('rekey', gen) | ('dup', gen) | None."""
        self._check_open()
        while len(self.rbuf) < 2:
            chunk = self.io.read(2 - len(self.rbuf))
            if not chunk:
                return None
            self.rbuf += chunk
        (ln,) = struct.unpack('!H', self.rbuf[:2])
        while len(self.rbuf) < 2 + ln:
            chunk = self.io.read(2 + ln - len(self.rbuf))
            if not chunk:
                return None
            self.rbuf += chunk
        ct = bytes(self.rbuf[2:2 + ln])
        del self.rbuf[:2 + ln]

        cs = self._recv_cs()
        nonce, fp = cs.n, keyfp(cs)
        try:
            pt = self.noise.decrypt(ct)
        except NoiseMaxNonceError:
            self._close('nonce exhausted')
            raise ConnectionClosed(self.closed)
        except Exception:
            # Old-generation, replayed, reordered or forged record. We do NOT
            # try any historical keys; failure is final.
            self._close('AEAD authentication failed at recv nonce {} '
                        '(old-generation/replayed/forged record); '
                        'no historical keys tried'.format(nonce))
            raise ConnectionClosed(self.closed)

        rtype, body = pt[0], pt[1:]
        self.tracer.log('dec', self.name, self.recv_gen, nonce, fp, rtype,
                        'body={!r}'.format(body[:32]))

        if rtype == T_APP:
            return ('app', body)

        if rtype == T_REKEY:
            (gen,) = struct.unpack('!Q', body)
            if gen == self.recv_gen + 1:
                self.noise.rekey_inbound_cipher()
                self.recv_gen += 1
                self.tracer.note(
                    '{}: recv boundary crossed -> gen={} '
                    '(record at nonce {} was the LAST under the old key; '
                    'nonce {} is the FIRST under the new key {})'.format(
                        self.name, self.recv_gen, nonce, nonce + 1,
                        keyfp(self._recv_cs())))
                return ('rekey', gen)
            if gen == self.recv_gen:
                self.tracer.note('{}: duplicate REKEY(gen={}) - ignored'.format(
                    self.name, gen))
                return ('dup', gen)
            self._close('REKEY generation {} out of window (recv_gen={})'.format(
                gen, self.recv_gen))
            raise ConnectionClosed(self.closed)

        self._close('unknown record type 0x{:02x}'.format(rtype))
        raise ConnectionClosed(self.closed)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def make_endpoint_pair():
    a, b = MemoryEndpoint('A-io'), MemoryEndpoint('B-io')
    a.connect(b)
    b.connect(a)
    return a, b


def main():
    tracer = Tracer()

    print('=== Phase 0: Noise_XX handshake (mutually authenticated channel) ===')
    a_io, b_io = make_endpoint_pair()

    a_noise = NoiseConnection.from_name(b'Noise_XX_25519_ChaChaPoly_BLAKE2s')
    b_noise = NoiseConnection.from_name(b'Noise_XX_25519_ChaChaPoly_BLAKE2s')
    a_noise.set_as_initiator()
    b_noise.set_as_responder()
    a_noise.noise_protocol.keypairs['s'] = a_noise.noise_protocol.dh_fn.generate_keypair()
    b_noise.noise_protocol.keypairs['s'] = b_noise.noise_protocol.dh_fn.generate_keypair()
    a_noise.start_handshake()
    b_noise.start_handshake()
    # XX: -> e / <- e, ee, s, es / -> s, se
    b_io.inbuf += a_noise.write_message()
    b_noise.read_message(bytes(b_io.inbuf)); b_io.inbuf.clear()
    a_io.inbuf += b_noise.write_message()
    a_noise.read_message(bytes(a_io.inbuf)); a_io.inbuf.clear()
    b_io.inbuf += a_noise.write_message()
    b_noise.read_message(bytes(b_io.inbuf)); b_io.inbuf.clear()
    assert a_noise.handshake_finished and b_noise.handshake_finished
    print('  handshake finished, channel authenticated (XX, both static keys verified)')

    A = RekeyRecordLayer(a_noise, a_io, 'A', tracer)
    B = RekeyRecordLayer(b_noise, b_io, 'B', tracer)

    print('\n=== Phase 1: application records, generation 0, both directions ===')
    A.send_app(b'hello-0')
    B.send_app(b'hi-0')
    A.send_app(b'hello-1')
    print('  B.recv ->', B.recv())
    print('  A.recv ->', A.recv())
    print('  B.recv ->', B.recv())

    print('\n=== Phase 2: A initiates rekey A->B; control record write FAILS halfway ===')
    a_io.fail_after = 7  # transport dies after 7 bytes of the REKEY frame
    A.initiate_rekey()
    print('  B.recv while frame incomplete ->', B.recv())
    try:
        A.send_app(b'blocked')
    except SendBlocked as e:
        print('  A.send_app during pending rekey -> SendBlocked:', e)

    print('\n=== Phase 3: B initiates rekey B->A CONCURRENTLY (directions independent) ===')
    B.initiate_rekey()
    B.send_app(b'hi-1 (B gen 1)')
    print('  A.recv ->', A.recv())   # REKEY for B->A direction
    print('  A.recv ->', A.recv())   # app record under B's new key

    print('\n=== Phase 4: A flushes the rest of its REKEY frame; boundary takes effect ===')
    A.flush()
    A.send_app(b'hello-2 (A gen 1)')
    print('  B.recv ->', B.recv())   # REKEY for A->B direction
    print('  B.recv ->', B.recv())   # app record under A's new key

    print('\n=== Phase 5: duplicate control record (re-sent under the new key) ===')
    A.initiate_rekey()   # REKEY(gen=2); B will apply it...
    print('  B.recv ->', B.recv())
    # ...then a buggy/duplicating peer logic sends REKEY(gen=2) AGAIN under the
    # now-current key. It decrypts fine, but gen == recv_gen -> ignored.
    A._enqueue(A._frame(T_REKEY, struct.pack('!Q', 2)), is_rekey=False)
    print('  B.recv ->', B.recv())

    print('\n=== Phase 6: old-generation record replayed late -> deterministic close ===')
    A.send_app(b'record at gen 2')
    print('  B.recv ->', B.recv())
    captured = a_io.sent_log[-1]   # attacker/reorder taps a gen-2 record
    A.initiate_rekey()             # A->B moves to generation 3
    print('  B.recv ->', B.recv())
    A.send_app(b'fresh record (A gen 3)')
    print('  B.recv ->', B.recv())
    # ...and only now does the old-generation record (re)appear on the wire.
    b_io.inbuf += captured
    try:
        B.recv()
    except ConnectionClosed as e:
        print('  B.recv on replayed old-generation record -> ConnectionClosed:', e)
    try:
        B.send_app(b'any')
    except ConnectionClosed as e:
        print('  B.send_app after close -> ConnectionClosed:', e)

    print('\n=== Close conditions (all final) ===')
    for c in ('AEAD authentication failure (old-generation / replay / forgery) - '
              'historical keys are never tried',
              'unknown record type',
              'REKEY generation outside {recv_gen, recv_gen+1}',
              'nonce exhaustion (rekey does NOT reset the nonce)'):
        print('  -', c)


if __name__ == '__main__':
    main()
