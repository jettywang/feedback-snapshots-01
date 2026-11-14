#! /usr/bin/env python

"""
Implementation of BIP-340 Schnorr signatures over the secp256k1 curve.

This module implements the x-only Schnorr signature scheme specified in
`BIP-340 <https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki>`_.
It is a standalone protocol built directly on the secp256k1 point
arithmetic from :py:mod:`ecdsa.ecdsa` and :py:mod:`ecdsa.ellipticcurve`.

.. note ::
    Schnorr signatures (BIP-340) are a *different* protocol from ECDSA.
    The interface in this module is intentionally independent from
    :py:mod:`ecdsa.keys`: there is no configurable ``hashfunc`` (the
    tagged SHA-256 hashes are fixed by the specification), signatures
    are fixed 64-byte strings (no DER encoding) and no low-S
    normalisation is applied. The two schemes must not be used
    interchangeably; this module does not try to detect or accept
    ECDSA signatures.

Differences from the ECDSA API:

* public keys are 32-byte x-only encodings (the implicit y coordinate
  is always even),
* secret keys are 32-byte strings,
* messages are exactly 32 bytes (hash longer messages yourself, e.g.
  with SHA-256, before signing),
* signatures are exactly 64 bytes: the 32-byte x coordinate of the
  nonce point ``R`` followed by the 32-byte scalar ``s``,
* signing requires an explicit 32-byte auxiliary random value
  (``aux_rand``); pass 32 zero bytes if a fully deterministic
  signature is desired.

.. warning ::
    This is a pure Python implementation. None of the operations are
    constant-time, so the private key operations (:func:`sign` and
    :func:`pubkey_gen`) must not be used with production secret keys
    in environments where an attacker can observe timing, cache or
    other side channels. They are appropriate for testing,
    experimentation and offline use with throwaway keys. :func:`verify`
    only handles public data, but is not constant-time either.

Example (using a fixed test key from the BIP-340 test vectors, do not
use this key for anything real):

.. code-block:: python

   from ecdsa import schnorr

   secret_key = bytes(bytearray.fromhex(
       "0000000000000000000000000000000000000000000000000000000000000003"))
   public_key = schnorr.pubkey_gen(secret_key)
   msg = bytes(bytearray(32))
   aux_rand = bytes(bytearray(32))

   signature = schnorr.sign(secret_key, msg, aux_rand)
   assert schnorr.verify(public_key, msg, signature)
"""

import hashlib
from . import ellipticcurve
from .ecdsa import curve_secp256k1, generator_secp256k1
from ._compat import compat26_str, int_to_bytes, bytes_to_int

__all__ = ["pubkey_gen", "sign", "verify", "lift_x"]


_p = curve_secp256k1.p()
_n = generator_secp256k1.order()
_G = generator_secp256k1


def _sha256(data):
    return hashlib.sha256(compat26_str(data)).digest()


def _tagged_hash(tag, msg):
    """Return SHA256(SHA256(tag) || SHA256(tag) || msg)."""
    tag_hash = _sha256(tag.encode("ascii"))
    return _sha256(tag_hash + tag_hash + msg)


def _bytes32(num):
    return int_to_bytes(num, 32)


def lift_x(x):
    """
    Return the curve point with the given x coordinate and even y.

    :param int x: the x coordinate, must be in range [0, p-1]
    :return: the point (x, y) on secp256k1 with even y
    :rtype: ecdsa.ellipticcurve.Point
    :raises ValueError: if x is out of range or is not the x coordinate
        of any curve point
    """
    if not 0 <= x < _p:
        raise ValueError(
            "x coordinate {0} outside of the field [0, p-1]".format(x)
        )
    y_sq = (pow(x, 3, _p) + 7) % _p
    # p % 4 == 3, so the square root, if it exists, is y_sq**((p+1)/4)
    y = pow(y_sq, (_p + 1) // 4, _p)
    if pow(y, 2, _p) != y_sq:
        raise ValueError(
            "x coordinate {0} does not correspond to a curve point".format(x)
        )
    if y & 1:
        y = _p - y
    return ellipticcurve.Point(curve_secp256k1, x, y, _n)


def _decode_secret_key(secret_key):
    if len(secret_key) != 32:
        raise ValueError(
            "The secret key must be exactly 32 bytes, got {0}".format(
                len(secret_key)
            )
        )
    d0 = bytes_to_int(secret_key, "big")
    if not 1 <= d0 <= _n - 1:
        raise ValueError(
            "The secret key must be an integer in range [1, n-1]"
        )
    return d0


def pubkey_gen(secret_key):
    """
    Compute the x-only public key for the given secret key.

    :param bytes secret_key: 32-byte secret key
    :return: 32-byte x-only public key
    :rtype: bytes
    :raises ValueError: if the secret key is malformed
    """
    d0 = _decode_secret_key(secret_key)
    P = _G * d0
    return bytes(_bytes32(P.x()))


def sign(secret_key, msg, aux_rand):
    """
    Create a BIP-340 Schnorr signature over the 32-byte message.

    :param bytes secret_key: 32-byte secret key
    :param bytes msg: 32-byte message to sign
    :param bytes aux_rand: 32 bytes of explicit auxiliary randomness;
        use 32 zero bytes for fully deterministic signatures
    :return: 64-byte signature
    :rtype: bytes
    :raises ValueError: if any input has incorrect length or the secret
        key is invalid
    """
    if len(msg) != 32:
        raise ValueError(
            "The message must be exactly 32 bytes, got {0}".format(len(msg))
        )
    if len(aux_rand) != 32:
        raise ValueError(
            "The auxiliary randomness must be exactly 32 bytes, "
            "got {0}".format(len(aux_rand))
        )
    d0 = _decode_secret_key(secret_key)
    P = _G * d0
    if P.y() & 1:
        d = _n - d0
    else:
        d = d0
    px = _bytes32(P.x())
    t = bytearray(
        a ^ b
        for a, b in zip(
            bytearray(_bytes32(d)),
            bytearray(_tagged_hash("BIP0340/aux", aux_rand)),
        )
    )
    k0 = (
        bytes_to_int(_tagged_hash("BIP0340/nonce", t + px + msg), "big") % _n
    )
    if k0 == 0:
        raise RuntimeError(
            "The derived nonce is zero, this happens with probability "
            "2**-128; retry with different auxiliary randomness"
        )
    R = _G * k0
    if R.y() & 1:
        k = _n - k0
    else:
        k = k0
    rx = _bytes32(R.x())
    e = (
        bytes_to_int(_tagged_hash("BIP0340/challenge", rx + px + msg), "big")
        % _n
    )
    sig = rx + _bytes32((k + e * d) % _n)
    if not verify(bytes(px), msg, bytes(sig)):
        raise RuntimeError(
            "The created signature failed verification, this is a bug"
        )
    return bytes(sig)


def verify(public_key, msg, signature):
    """
    Verify a BIP-340 Schnorr signature.

    Returns False for any malformed input: wrong lengths, public key
    that is not a liftable x coordinate, ``r`` or ``s`` out of range.

    :param bytes public_key: 32-byte x-only public key
    :param bytes msg: 32-byte message
    :param bytes signature: 64-byte signature
    :return: True if the signature is valid, False otherwise
    :rtype: bool
    """
    if len(public_key) != 32 or len(msg) != 32 or len(signature) != 64:
        return False
    px = bytes_to_int(public_key, "big")
    r = bytes_to_int(signature[:32], "big")
    s = bytes_to_int(signature[32:], "big")
    if px >= _p or r >= _p or s >= _n:
        return False
    try:
        P = lift_x(px)
    except ValueError:
        return False
    e = (
        bytes_to_int(
            _tagged_hash(
                "BIP0340/challenge", signature[:32] + public_key + msg
            ),
            "big",
        )
        % _n
    )
    R = _G * s + P * ((-e) % _n)
    if R == ellipticcurve.INFINITY:
        return False
    if R.y() & 1:
        return False
    return R.x() == r
