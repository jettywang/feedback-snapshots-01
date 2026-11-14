import sys, warnings
warnings.simplefilter("ignore")
sys.path.insert(0, "/Users/apple/Documents/用户反馈项目/run-control/first-five/jobs/FB-20261114-SEC14-097/workspace-002")

from noise.connection import NoiseConnection, Keypair
from noise.backends.default.keypairs import KeyPair25519
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization

def kp(seed):
    return KeyPair25519.from_private_bytes(bytes([seed])*32)

init_s, resp_s = kp(1), kp(2)
PSK = bytes([0xAA])*32

def fresh(name, role, static=None, rstatic=None, psk=None):
    c = NoiseConnection.from_name(name)
    if psk is not None: c.set_psks(psk)
    if role == "init": c.set_as_initiator()
    else: c.set_as_responder()
    if static:  c.set_keypair_from_private_bytes(Keypair.STATIC, static.private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
    if rstatic: c.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, rstatic.public_bytes)
    c.start_handshake()
    return c

def has_key(conn):
    cs = conn.noise_protocol.cipher_state_handshake
    return cs.has_key() if not isinstance(cs, type(None)) and not conn.handshake_finished else \
           (conn.handshake_finished and conn.noise_protocol.cipher_state_encrypt.has_key())

print("="*78)
print("EXP 0  baseline: handshake wire layout + at which point an AEAD key exists")
print("="*78)

# ---------- NNpsk0: 2 messages ----------
a = fresh(b"Noise_NNpsk0_25519_ChaChaPoly_SHA256", "init", psk=PSK)
b = fresh(b"Noise_NNpsk0_25519_ChaChaPoly_SHA256", "resp", psk=PSK)
m1 = a.write_message(b"req-1")
print(f"\n[NNpsk0] msg1 len={len(m1)} (e=32B + payload+16B tag -> {32}+{len(b'req-1')+16})")
print("         initiator has AEAD key after writing msg1? ", a.noise_protocol.cipher_state_handshake.has_key())
p1 = b.read_message(m1)
m2 = b.write_message(b"rsp-1")
a.read_message(m2)
print(f"[NNpsk0] msg2 len={len(m2)}; handshake_finished both: {a.handshake_finished and b.handshake_finished}")
print(f"[NNpsk0] responder decrypted msg1 payload: {bytes(p1)!r}")

# ---------- XX: 3 messages ----------
a = fresh(b"Noise_XX_25519_ChaChaPoly_SHA256", "init", static=init_s)
b = fresh(b"Noise_XX_25519_ChaChaPoly_SHA256", "resp", static=resp_s)
m1 = a.write_message(b"cleartext-payload")
print(f"\n[XX]     msg1 len={len(m1)} (only e=32B, NO key yet -> payload is cleartext)")
print("         initiator has AEAD key at msg1? ", a.noise_protocol.cipher_state_handshake.has_key())
print(f"         msg1 payload literally on the wire: {b'req' in m1 or b'cleartext-payload' in m1}, "
      f"found {b'cleartext-payload' in bytes(m1)}")
b.read_message(m1)
m2 = b.write_message(b"enc2")
print(f"[XX]     msg2 len={len(m2)} (e=32 + s=48 + payload+16)")
a.read_message(m2)
print("         initiator now holds remote static rs? ",
      not isinstance(a.noise_protocol.handshake_state.rs, type(a.noise_protocol.handshake_state.e)))
m3 = a.write_message(b"enc3")
b.read_message(m3)
print(f"[XX]     msg3 len={len(m3)} (s=48 + payload+16); finished: {a.handshake_finished and b.handshake_finished}")
rs_seen_by_init = a.noise_protocol.handshake_hash  # after done, handshake_state deleted
print("[XX]     after split, handshake_state is deleted -> rs no longer reachable via NoiseConnection API")

# ---------- IK: 2 messages ----------
a = fresh(b"Noise_IK_25519_ChaChaPoly_SHA256", "init", static=init_s, rstatic=resp_s)
b = fresh(b"Noise_IK_25519_ChaChaPoly_SHA256", "resp", static=resp_s, rstatic=init_s)
m1 = a.write_message(b"first-business-payload")
print(f"\n[IK]     msg1 len={len(m1)} (e=32 + enc s=48 + payload+16); initiator has key? ",
      a.noise_protocol.cipher_state_handshake.has_key(), ")")
print(f"         initiator static visible in clear on wire? {init_s.public_bytes in bytes(m1)} (False=identity hidden)")
p1 = b.read_message(m1)
m2 = b.write_message(b"second")
a.read_message(m2)
print(f"[IK]     msg1 payload decrypted by authenticated responder: {bytes(p1)!r}; finished {a.handshake_finished}")

print("\ntransport keys are session-unique:")
a1 = fresh(b"Noise_IK_25519_ChaChaPoly_SHA256", "init", init_s, resp_s)
b1 = fresh(b"Noise_IK_25519_ChaChaPoly_SHA256", "resp", resp_s, init_s)
b1.read_message(a1.write_message()); a1.read_message(b1.write_message())
a2 = fresh(b"Noise_IK_25519_ChaChaPoly_SHA256", "init", init_s, resp_s)
b2 = fresh(b"Noise_IK_25519_ChaChaPoly_SHA256", "resp", resp_s, init_s)
b2.read_message(a2.write_message()); a2.read_message(b2.write_message())
k1 = a1.noise_protocol.cipher_state_encrypt.k
k2 = a2.noise_protocol.cipher_state_encrypt.k
print(f"  session1 outbound key: {k1.hex()[:32]}...")
print(f"  session2 outbound key: {k2.hex()[:32]}...")
print(f"  equal despite identical static keys? {k1 == k2}  (ephemeral DH makes them independent)")
