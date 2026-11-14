"""
Explicit ECDSA protocol shared by a gateway and a backend.

The gateway hashes the message itself; the backend verifies a precomputed
digest. Both import the SAME SignatureProtocol, so they cannot disagree just
because the generic ecdsa API gives ``verify`` and ``verify_digest``
different default arguments.

Run with: python docs/examples/protocol_gateway_backend.py
"""

from hashlib import sha256, sha384

from ecdsa import NIST256p, SigningKey
from ecdsa import protocol
from ecdsa.util import sigdecode_string, sigencode_string_canonize

ORDER = NIST256p.order

# One object binds curve, hash, wire encoding, truncation and low-S.
shared = protocol.SignatureProtocol(
    curve=NIST256p,
    hashfunc=sha256,
    encoding=protocol.RAW,
    allow_truncate=False,
    require_low_s=True,
)

sk = SigningKey.generate(curve=NIST256p, hashfunc=sha256)
vk = sk.get_verifying_key()
message = b"transfer 10"
signature = sk.sign(message, hashfunc=sha256, sigencode=sigencode_string_canonize)


def gateway(sig, msg):
    # Hashes the message, then runs the shared rules.
    return shared.verify_message(vk, sig, msg)


def backend(sig, msg):
    # Receives a precomputed digest (e.g. from a HSM), never re-hashes.
    return shared.verify_digest(vk, sig, sha256(msg).digest())


print("canonical signature accepted on both paths:")
print("  gateway:", gateway(signature, message))
print("  backend:", backend(signature, message))

r, s = sigdecode_string(signature, ORDER)
high_s = r.to_bytes(32, "big") + (ORDER - s).to_bytes(32, "big")

print("\nhigh-S is a valid mathematical signature but a policy violation:")
for label, call in (
    ("gateway", lambda: gateway(high_s, message)),
    ("backend", lambda: backend(high_s, message)),
):
    try:
        call()
    except protocol.HighSRejection as error:
        print("  {0}: HighSRejection -> {1}".format(label, error))

print("\ntampering changes the math, not the policy:")
broken = bytearray(signature)
broken[0] ^= 0x01
try:
    gateway(bytes(broken), message)
except protocol.MathVerificationFailure as error:
    print("  MathVerificationFailure ->", error)

print("\ntruncation is one shared switch (SHA-384 over NIST256p):")
sk384 = SigningKey.generate(curve=NIST256p, hashfunc=sha384)
sig384 = sk384.sign(
    message,
    hashfunc=sha384,
    sigencode=sigencode_string_canonize,
    allow_truncate=True,
)
strict384 = protocol.SignatureProtocol(
    curve=NIST256p, hashfunc=sha384, allow_truncate=False
)
try:
    strict384.verify_message(sk384.get_verifying_key(), sig384, message)
except protocol.DigestLengthRejection as error:
    print("  strict -> DigestLengthRejection:", error)
