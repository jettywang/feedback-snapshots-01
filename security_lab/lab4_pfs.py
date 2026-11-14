import sys, warnings, os
warnings.simplefilter("ignore")
sys.path.insert(0, "/Users/apple/Documents/用户反馈项目/run-control/first-five/jobs/FB-20261114-SEC14-097/workspace-002")

from noise.connection import NoiseConnection, Keypair
from noise.backends.default.keypairs import KeyPair25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

def priv(k): return k.private.private_bytes(serialization.Encoding.Raw,
                                            serialization.PrivateFormat.Raw,
                                            serialization.NoEncryption())
def kp(seed): return KeyPair25519.from_private_bytes(bytes([seed])*32)
i_s, r_s = kp(1), kp(2)

def ik(role, static, rstatic):
    c = NoiseConnection.from_name(b"Noise_IK_25519_ChaChaPoly_SHA256")
    c.set_as_initiator() if role == "init" else c.set_as_responder()
    c.set_keypair_from_private_bytes(Keypair.STATIC, priv(static))
    c.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, rstatic.public_bytes)
    c.start_handshake(); return c

print("="*78)
print("EXP 4  static key compromise — what the attacker can and cannot reconstruct")
print("="*78)

# Record one full historical session off the wire
a = ik("init", i_s, r_s); b = ik("resp", r_s, i_s)
w1 = bytes(a.write_message(b"historical-request"))
w2 = bytes(b.read_message(w1) and b.write_message(b"historical-reply"))
a.read_message(w2)
t1 = bytes(a.encrypt(b"historical-transport"))
b.decrypt(t1)
k_init = bytes(a.noise_protocol.cipher_state_encrypt.k)
k_resp = bytes(b.noise_protocol.cipher_state_encrypt.k)
h_hash = a.get_handshake_hash().hex()[:16]
print(f"\nhistorical session recorded: msg1={len(w1)}B msg2={len(w2)}B transport={len(t1)}B")
print(f"handshake_hash={h_hash}...  transport keys never appear on the wire")

# Attacker later steals BOTH static private keys and has the full recording
stolen_init = priv(i_s); stolen_resp = priv(r_s)
# every recorded message's static s token decrypts fine (public material) - but session key
# was derived through DH(e, re)/DH(e,rs)/DH(s,re)/DH(s,rs). Ephemeral private e is gone:
print("\npost-compromise check, what survives in the library process after split():")
for name, conn in (("initiator", a), ("responder", b)):
    np = conn.noise_protocol
    hs_gone = not hasattr(np, "handshake_state")
    print(f"  {name}: handshake_state/ephemeral e deleted? {hs_gone}; only transport CipherStates remain")

# Can attacker brute the session from wire + static keys alone? Demonstrate missing input:
# msg1 begins with ephemeral PUBLIC e; the corresponding private x exists only in RAM at session time.
e_pub = w1[:32]
# X25519 exchange needs a private scalar; attacker only has statics, not x:
attacker_e = X25519PrivateKey.generate()  # any guess != original x gives unrelated shared secret
guessed = attacker_e.exchange(KeyPair25519.from_public_bytes(w2[:32]).public)
real = None  # original x was in initiator RAM and was deleted
print(f"\nattacker recomputes DH with a random scalar -> {guessed.hex()[:16]}... (no relation to real ee secret)")
print("the real ephemeral private scalar is not derivable from static keys (X25519 discrete-log assumption)")

# What static compromise DOES buy: impersonation in a NEW session
print("\nwhat the leak enables instead — impersonation in a future session:")
evil = ik("init", i_s, r_s)          # attacker uses stolen initiator static
srv  = ik("resp", r_s, i_s)          # server pins that very key
m1 = evil.write_message(b"fraudulent-new-request")
p = srv.read_message(m1)
srv.read_message  # noop
srv.write_message(b"ok")
print(f"  new session accepted, responder decrypts attacker payload: {bytes(p)!r}")
print("  => static leak breaks FUTURE authentication, not PAST confidentiality (PFS held)")

# NNpsk0 compromise contrast
print("\n" + "="*78)
print("EXP 5  PSK compromise contrast (NNpsk0)")
print("="*78)
PSK = bytes([0xAA])*32
def psk_conn(role, psk):
    c = NoiseConnection.from_name(b"Noise_NNpsk0_25519_ChaChaPoly_SHA256")
    c.set_psks(psk)
    c.set_as_initiator() if role == "init" else c.set_as_responder()
    c.start_handshake(); return c
a = psk_conn("init", PSK); b = psk_conn("resp", PSK)
w1 = bytes(a.write_message(b"psk-msg1-secret"))
b.read_message(w1)
w2 = bytes(b.write_message(b"psk-msg2")); a.read_message(w2)
t = bytes(a.encrypt(b"psk-transport-secret"))
# attacker with PSK and the recording:
aa = psk_conn("init", PSK)
# msg1 key schedule only needs PSK + wire public e (and in psk0, MixKey(e.public)) -> decryptable offline
# simulate offline decrypt by replaying into a fresh responder-style decryptor:
spy = psk_conn("resp", PSK)
p1 = spy.read_message(w1)
print(f"holder of PSK decrypts recorded msg1 offline via fresh state: {bytes(p1)!r}")
print(f"recorded transport decryptable with PSK alone? session key also needs ephemeral DH(e,re) outputs")
print("  -> msg1 retroactively exposed; later messages still protected by ephemeral DH (same PFS logic)")

print("\n" + "="*78)
print("EXP 6  identity hiding summary (passive observer)")
print("="*78)
# IK msg1 static is encrypted; XX msg2/msg3 static encrypted; NNpsk0 has no static at all
a = ik("init", i_s, r_s); b = ik("resp", r_s, i_s)
w1 = bytes(a.write_message(b""))
print(f"IK  msg1 leaks initiator static pubkey on wire? {i_s.public_bytes in w1}")
print(f"IK  responder identity: pre-message rs is a LOCAL pin, not sent; passive observer cannot tell which rs")
xx_i = NoiseConnection.from_name(b"Noise_XX_25519_ChaChaPoly_SHA256")
xx_i.set_as_initiator(); xx_i.set_keypair_from_private_bytes(Keypair.STATIC, priv(i_s)); xx_i.start_handshake()
xx_r = NoiseConnection.from_name(b"Noise_XX_25519_ChaChaPoly_SHA256")
xx_r.set_as_responder(); xx_r.set_keypair_from_private_bytes(Keypair.STATIC, priv(r_s)); xx_r.start_handshake()
x1 = bytes(xx_i.write_message(b"")); xx_r.read_message(x1)
x2 = bytes(xx_r.write_message(b""))
print(f"XX  msg2 leaks responder static pubkey on wire? {r_s.public_bytes in x2} (encrypted after EE)")
print("NNpsk0: no static tokens at all -> no cryptographic identity, only shared-PSK group membership")
