import sys, warnings, traceback
warnings.simplefilter("ignore")
sys.path.insert(0, "/Users/apple/Documents/用户反馈项目/run-control/first-five/jobs/FB-20261114-SEC14-097/workspace-002")

from noise.connection import NoiseConnection, Keypair
from noise.backends.default.keypairs import KeyPair25519
from noise.constants import Empty
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag

def priv(k):
    return k.private.private_bytes(serialization.Encoding.Raw,
                                   serialization.PrivateFormat.Raw,
                                   serialization.NoEncryption())
def kp(seed): return KeyPair25519.from_private_bytes(bytes([seed])*32)
init_s, resp_s, mallory_s = kp(1), kp(2), kp(9)

def fresh(name, role, static=None, rstatic=None):
    c = NoiseConnection.from_name(name)
    if role == "init": c.set_as_initiator()
    else: c.set_as_responder()
    if static:  c.set_keypair_from_private_bytes(Keypair.STATIC, priv(static))
    if rstatic: c.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, rstatic.public_bytes)
    c.start_handshake()
    return c

def label(ex):
    return type(ex).__name__

print("="*78)
print("EXP 1  wrong STATIC key — where exactly does the AEAD tag fail?")
print("="*78)

# 1a. IK initiator pins a WRONG responder static key
print("\n[1a] IK: initiator configured with wrong rs (responder impersonation attempt)")
a = fresh(b"Noise_IK_25519_ChaChaPoly_SHA256", "init", init_s, rstatic=mallory_s)
b = fresh(b"Noise_IK_25519_ChaChaPoly_SHA256", "resp", resp_s, rstatic=init_s)
m1 = a.write_message(b"business")
try:
    b.read_message(m1)   # responder tries to decrypt ES-protected payload with its real s
    print("  UNEXPECTED: handshake accepted")
except Exception as ex:
    print(f"  responder read_message -> {label(ex)}: {ex}  (ES DH mismatch => tag fails at MSG 1)")

# 1b. IK responder pins a WRONG initiator static key (msg1 still parses; failure moves to msg2)
print("\n[1b] IK: responder configured with wrong initiator rs (init auth delayed to msg2)")
a = fresh(b"Noise_IK_25519_ChaChaPoly_SHA256", "init", init_s, rstatic=resp_s)
b = fresh(b"Noise_IK_25519_ChaChaPoly_SHA256", "resp", resp_s, rstatic=mallory_s)
m1 = a.write_message(b"business")
p1 = b.read_message(m1)   # ES + SS use responder's own s and the s just received -> works
print(f"  msg1 accepted, payload={bytes(p1)!r}; responder derives msg2 with wrong rs via SE token")
m2 = b.write_message(b"reply")
try:
    a.read_message(m2)
    print("  msg2 also parses: both peers finish handshake (library cannot know pinned rs differs)")
    print(f"  initiator finished={a.handshake_finished}, responder finished={b.handshake_finished}")
    # now try actual transport data: responder encrypted with its split key
    ct = b.encrypt(b"transport-secret")
    try:
        a.decrypt(ct)
        print("  UNEXPECTED: transport decrypt accepted")
    except Exception as ex:
        print(f"  initiator transport decrypt -> {label(ex)}: split keys diverge, first real data fails")
except Exception as ex:
    print(f"  initiator read_message -> {label(ex)}: {ex}")

# 1c. XX: no pinned key, active MITM runs two independent handshakes
print("\n[1c] XX: full man-in-the-middle with no preconfigured key (TOFU gap)")
# client <-> mallory-as-responder
ca = fresh(b"Noise_XX_25519_ChaChaPoly_SHA256", "init", init_s)
mR = fresh(b"Noise_XX_25519_ChaChaPoly_SHA256", "resp", mallory_s)
m1 = ca.write_message(b"")
mR.read_message(m1)
m2 = mR.write_message(b"")
ca.read_message(m2)
rs_client_side = ca.noise_protocol.handshake_state.rs
m3 = ca.write_message(b"")
mR.read_message(m3)
print(f"  client side handshake finished={ca.handshake_finished}, rs it learned = {rs_client_side.public_bytes.hex()[:16]}...")
print(f"  real responder key                       = {resp_s.public_bytes.hex()[:16]}...")
print(f"  client actually pinned Mallory? {rs_client_side.public_bytes == mallory_s.public_bytes}  (no library error raised)")
# mallory-as-initiator <-> real server
mI = fresh(b"Noise_XX_25519_ChaChaPoly_SHA256", "init", mallory_s)
srv = fresh(b"Noise_XX_25519_ChaChaPoly_SHA256", "resp", resp_s)
srv.read_message(mI.write_message(b""))
mI.read_message(srv.write_message(b""))
m3s = mI.write_message(b"")
srv.read_message(m3s)
# rs must be captured BEFORE the last read_message triggers split()+handshake_done()
rs_server_side = mI.noise_protocol.handshake_state.rs if False else None
# responder-side rs: re-run and snapshot mid-handshake
mI2 = fresh(b"Noise_XX_25519_ChaChaPoly_SHA256", "init", mallory_s)
srv2 = fresh(b"Noise_XX_25519_ChaChaPoly_SHA256", "resp", resp_s)
srv2.read_message(mI2.write_message(b""))
mI2.read_message(srv2.write_message(b""))
srv2.read_message(mI2.write_message(b""))
# snapshot via a fresh handshake intercepted at msg3 boundary
mI3 = fresh(b"Noise_XX_25519_ChaChaPoly_SHA256", "init", mallory_s)
srv3 = fresh(b"Noise_XX_25519_ChaChaPoly_SHA256", "resp", resp_s)
srv3.read_message(mI3.write_message(b""))
mI3.read_message(srv3.write_message(b""))
# responder holds rs right after parsing msg3 but split deletes state; emulate by monkeypatch
orig_split = srv3.noise_protocol.handshake_state.symmetric_state.split
captured = {}
def spy_split():
    captured["rs"] = srv3.noise_protocol.handshake_state.rs.public_bytes
    return orig_split()
srv3.noise_protocol.handshake_state.symmetric_state.split = spy_split
srv3.read_message(mI3.write_message(b""))
rs_server_side = type("K", (), {"public_bytes": captured["rs"]})()
print(f"  server side handshake finished={srv.handshake_finished}, rs it learned = {rs_server_side.public_bytes.hex()[:16]}...")
print(f"  server actually pinned Mallory? {rs_server_side.public_bytes == mallory_s.public_bytes}")

# 1d. XX with tampered msg2 byte -> tag failure
print("\n[1d] XX: flip one byte of encrypted msg2 (active tampering, no MITM key knowledge)")
a = fresh(b"Noise_XX_25519_ChaChaPoly_SHA256", "init", init_s)
b = fresh(b"Noise_XX_25519_ChaChaPoly_SHA256", "resp", resp_s)
b.read_message(a.write_message(b""))
m2 = bytearray(b.write_message(b"enc2"))
m2[-1] ^= 0x01
try:
    a.read_message(bytes(m2))
    print("  UNEXPECTED accepted")
except Exception as ex:
    print(f"  -> {label(ex)}: integrity protection catches tampering")

# 1e. passive observer: what is visible on the wire
print("\n[1e] passive wire observer view (XX)")
a = fresh(b"Noise_XX_25519_ChaChaPoly_SHA256", "init", init_s)
b = fresh(b"Noise_XX_25519_ChaChaPoly_SHA256", "resp", resp_s)
w1 = bytes(a.write_message(b"CLEARTEXT-MARKER"))
b.read_message(w1)
w2 = bytes(b.write_message(b"SECRET-MARKER-2"))
a.read_message(w2)
w3 = bytes(a.write_message(b"SECRET-MARKER-3"))
b.read_message(w3)
print(f"  msg1 contains cleartext marker on wire? {b'CLEARTEXT-MARKER' in w1}")
print(f"  msg2 contains secret marker on wire?   {b'SECRET-MARKER-2' in w2}")
print(f"  msg3 contains secret marker on wire?   {b'SECRET-MARKER-3' in w3}")
print(f"  responder static key visible on wire in msg2? {resp_s.public_bytes in w2} (encrypted static s)")
print(f"  initiator static key visible on wire in msg3? {init_s.public_bytes in w3} (encrypted static s)")
