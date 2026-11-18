"""RSA / strong-name primitives used by the lab.

Signing uses PyCryptodome for key generation only.  Verification is a local
PKCS#1 v1.5 implementation so a bug in a signing helper cannot make an invalid
sample look valid.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from Crypto.PublicKey import RSA

from . import der

CALG_RSA_SIGN = 0x00002400
CALG_SHA1 = 0x00008004
CALG_SHA256 = 0x0000800C

HASH_OIDS = {
    "sha1": "1.3.14.3.2.26",
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
}
OID_HASHES = {value: name for name, value in HASH_OIDS.items()}
HASH_ALG_IDS = {CALG_SHA1: "sha1", CALG_SHA256: "sha256"}


class CryptoError(ValueError):
    pass


def digest(name: str, data: bytes) -> bytes:
    try:
        return hashlib.new(name, data).digest()
    except ValueError as exc:
        raise CryptoError(f"unsupported digest {name}") from exc


def digest_info(name: str, value: bytes) -> bytes:
    return der.sequence(der.algorithm_identifier(HASH_OIDS[name]), der.octet_string(value))


def pkcs1_v15_verify(modulus: int, exponent: int, signature: bytes, digest_info_der: bytes) -> tuple[bool, str]:
    """Strict RFC 8017 RSASSA-PKCS1-v1_5 verification.

    Returns (ok, reason).  The full encoded message is compared, not just the
    trailing digest, so padding tricks are rejected.
    """
    k = (modulus.bit_length() + 7) // 8
    if len(signature) != k:
        return False, f"signature length {len(signature)} != modulus length {k}"
    s = int.from_bytes(signature, "big")
    if s <= 0 or s >= modulus:
        return False, "signature representative out of range"
    em = pow(s, exponent, modulus).to_bytes(k, "big")
    padding_len = k - len(digest_info_der) - 3
    if padding_len < 8:
        return False, "modulus too small for DigestInfo"
    expected = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + digest_info_der
    if not hmac.compare_digest(em, expected):
        return False, "PKCS#1 v1.5 encoded message mismatch"
    return True, "PKCS#1 v1.5 encoded message matches"


def pkcs1_v15_sign(key: RSA.RsaKey, digest_info_der: bytes) -> bytes:
    k = (key.n.bit_length() + 7) // 8
    padding_len = k - len(digest_info_der) - 3
    if padding_len < 8:
        raise CryptoError("modulus too small for DigestInfo")
    em = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + digest_info_der
    return pow(int.from_bytes(em, "big"), key.d, key.n).to_bytes(k, "big")


def big_endian_signature_for_strong_name(signature: bytes) -> bytes:
    """Strong names store the CAPI signature little-endian."""
    return signature[::-1]


def strong_name_signature_to_be(signature: bytes) -> bytes:
    return signature[::-1]


def public_key_blob(key: RSA.RsaKey, hash_alg: int = CALG_SHA1) -> bytes:
    """Build the ECMA-335 Assembly.PublicKey blob (CAPI PUBLICKEYBLOB)."""
    modulus = key.n.to_bytes((key.n.bit_length() + 7) // 8, "big")
    blob = (
        struct.pack("<BBHI", 0x06, 0x02, 0, CALG_RSA_SIGN)
        + b"RSA1"
        + struct.pack("<II", key.n.bit_length(), key.e)
        + modulus[::-1]
    )
    return struct.pack("<III", CALG_RSA_SIGN, hash_alg, len(blob)) + blob


def parse_public_key_blob(blob: bytes) -> dict:
    if len(blob) < 12:
        raise CryptoError("public key blob shorter than 12-byte header")
    sig_alg, hash_alg, cb = struct.unpack_from("<III", blob, 0)
    if sig_alg != CALG_RSA_SIGN:
        raise CryptoError(f"unsupported signature algorithm 0x{sig_alg:08x}")
    if cb != len(blob) - 12:
        raise CryptoError("public key blob length field mismatch")
    capi = blob[12:]
    if len(capi) < 20:
        raise CryptoError("CAPI blob too short")
    btype, bversion, reserved, ai_key_alg = struct.unpack_from("<BBHI", capi, 0)
    if (btype, bversion, reserved) != (0x06, 0x02, 0):
        raise CryptoError("not a CAPI PUBLICKEYBLOB")
    if ai_key_alg != CALG_RSA_SIGN:
        raise CryptoError(f"unsupported CAPI key algorithm 0x{ai_key_alg:08x}")
    magic, bits, exponent = struct.unpack_from("<III", capi, 8)
    if magic != 0x31415352:
        raise CryptoError("missing RSA1 magic")
    expected = (bits + 7) // 8
    modulus_le = capi[20:]
    if len(modulus_le) != expected:
        raise CryptoError("RSA modulus length mismatch")
    modulus = int.from_bytes(modulus_le, "little")
    if (modulus.bit_length() + 7) // 8 != expected:
        raise CryptoError("RSA modulus bit length mismatch")
    return {
        "signature_algorithm": sig_alg,
        "hash_algorithm_id": hash_alg,
        "hash_algorithm": HASH_ALG_IDS.get(hash_alg, f"0x{hash_alg:08x}"),
        "bits": bits,
        "exponent": exponent,
        "modulus": modulus,
        "modulus_sha256": hashlib.sha256(modulus.to_bytes(expected, "big")).hexdigest(),
    }


def token_from_public_key_blob(blob: bytes) -> str:
    """Strong-name token: last 8 bytes of SHA-1(blob), reversed."""
    return hashlib.sha1(blob).digest()[-8:][::-1].hex()


def public_key_blob_sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()
