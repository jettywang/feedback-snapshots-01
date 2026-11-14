import sys, warnings
warnings.simplefilter("ignore")
sys.path.insert(0, "/Users/apple/Documents/用户反馈项目/run-control/first-five/jobs/FB-20261114-SEC14-097/workspace-002")

from noise.connection import NoiseConnection

PSK     = bytes([0xAA])*32
BAD_PSK = bytes([0xBB])*32

def fresh(name, role, psk):
    c = NoiseConnection.from_name(name)
    c.set_psks(psk)
    if role == "init": c.set_as_initiator()
    else: c.set_as_responder()
    c.start_handshake()
    return c

NAME = b"Noise_NNpsk0_25519_ChaChaPoly_SHA256"

print("="*78)
print("EXP 2  wrong PSK in NNpsk0 — which message's tag fails")
print("="*78)

# 2a responder holds wrong PSK
a = fresh(NAME, "init", PSK);     b = fresh(NAME, "resp", BAD_PSK)
m1 = a.write_message(b"order-42")
try:
    b.read_message(m1); print("  UNEXPECTED")
except Exception as ex:
    print(f"[2a] responder wrong PSK, read msg1 -> {type(ex).__name__}: PSK enters key schedule before msg1 tag")

# 2b initiator holds wrong PSK: responder fails already at msg1, because psk0 mixes in
# before the msg1 AEAD tag (MixKeyAndHash at the head of message pattern 1)
a = fresh(NAME, "init", BAD_PSK); b = fresh(NAME, "resp", PSK)
m1 = a.write_message(b"order-42")
try:
    b.read_message(m1); print("  UNEXPECTED")
except Exception as ex:
    print(f"[2b] initiator wrong PSK, responder read msg1 -> {type(ex).__name__}: "
          f"psk0 is mixed before the first tag, so ANY wrong PSK fails at msg1")

# 2c transport message tamper
a = fresh(NAME, "init", PSK); b = fresh(NAME, "resp", PSK)
b.read_message(a.write_message()); a.read_message(b.write_message())
ct = bytearray(a.encrypt(b"transport"))
ct[-1] ^= 0xFF
try:
    b.decrypt(bytes(ct)); print("  UNEXPECTED")
except Exception as ex:
    print(f"[2c] flipped transport byte -> {type(ex).__name__}: AEAD per-message integrity")

print()
print("="*78)
print("EXP 3  first-message replay — the library has no replay memory")
print("="*78)

# honest handshake, capture msg1 bytes
a = fresh(NAME, "init", PSK); b = fresh(NAME, "resp", PSK)
m1 = a.write_message(b"POST /transfer amount=1000 idempotency=7")
b.read_message(m1)
m2 = b.write_message(); a.read_message(m2)
print(f"[3a] original handshake finished={a.handshake_finished and b.handshake_finished}")

# replay into the SAME responder object
b2 = fresh(NAME, "resp", PSK)
b2.read_message(m1)   # consume pattern once
try:
    b2.read_message(m1)
    print("  UNEXPECTED")
except Exception as ex:
    print(f"[3b] replay into same state machine -> {type(ex).__name__}: only state-machine ordering guards this")

# replay into a FRESH responder (server reboot / another replica / no replay cache)
b3 = fresh(NAME, "resp", PSK)
p = b3.read_message(m1)
print(f"[3c] replay into FRESH responder accepted, payload={bytes(p)!r}")
m2r = b3.write_message()
# attacker also replays a second time against another fresh instance
b4 = fresh(NAME, "resp", PSK)
p4 = b4.read_message(m1)
print(f"     replay again into another fresh instance accepted, payload={bytes(p4)!r}")
# the original initiator is gone, but responder derived usable transport keys anyway
ct = b3.encrypt(b"server-to-ghost")
print(f"     responder happily produced transport ciphertext ({len(ct)}B) for a peer that does not exist")

# what an app-level replay cache keyed on ephemeral e (first 32 bytes) looks like
seen = set()
def cache_guard(raw_msg):
    nonce_key = bytes(raw_msg[:32])
    if nonce_key in seen:
        return "REJECTED: e already seen"
    seen.add(nonce_key)
    return "accepted"
print(f"[3d] app cache, first delivery:  {cache_guard(m1)}")
print(f"     app cache, replay:         {cache_guard(m1)}")

# IK replay behaves the same: fresh responder accepts
from noise.backends.default.keypairs import KeyPair25519
from noise.connection import Keypair
from cryptography.hazmat.primitives import serialization
def priv(k): return k.private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
i_s = KeyPair25519.from_private_bytes(bytes([1])*32)
r_s = KeyPair25519.from_private_bytes(bytes([2])*32)
def ik(role, static, rstatic):
    c = NoiseConnection.from_name(b"Noise_IK_25519_ChaChaPoly_SHA256")
    c.set_as_initiator() if role=="init" else c.set_as_responder()
    c.set_keypair_from_private_bytes(Keypair.STATIC, priv(static))
    c.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, rstatic.public_bytes)
    c.start_handshake(); return c
ai = ik("init", i_s, r_s); bi = ik("resp", r_s, i_s)
ik_m1 = ai.write_message(b"charge-card-now")
bi.read_message(ik_m1); bi.write_message()
bi2 = ik("resp", r_s, i_s)
p = bi2.read_message(ik_m1)
print(f"[3e] IK msg1 replay into fresh responder accepted too, payload={bytes(p)!r} (auth != anti-replay)")
