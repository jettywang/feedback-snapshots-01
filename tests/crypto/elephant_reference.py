"""Small, independent reference implementation of the BitLocker Elephant diffuser.

This module deliberately does not import :mod:`dissect.fve.crypto.elephant`.  It exists so
regression tests can derive and compare against fixed vectors without using the code that is
under test to produce its own expected answers.

The public references for the construction are libyal/libbde, dislocker and the BitLocker
format documentation from Microsoft.

The two diffuser stages operate on 32-bit little-endian words.  Encryption runs each stage
backwards with subtraction; decryption runs it forwards with addition.  Stage A uses the
preceding words (``i - 2`` and ``i - 5``) and stage B uses the following words (``i + 2`` and
``i + 5``).  All indices wrap around the sector.
"""

from __future__ import annotations

import struct

from Crypto.Cipher import AES

ROTATIONS_A = (9, 0, 13, 0)
ROTATIONS_B = (0, 10, 0, 25)


def _rotate_left(value: int, count: int) -> int:
    if count == 0:
        return value
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def _stage_a(data: bytes, cycles: int, decrypt: bool) -> bytes:
    words = list(struct.unpack(f"<{len(data) // 4}I", data))
    count = len(words)
    indices = range(count) if decrypt else range(count - 1, -1, -1)

    for _ in range(cycles):
        for i in indices:
            term = words[(i - 2) % count] ^ _rotate_left(words[(i - 5) % count], ROTATIONS_A[i % 4])
            if decrypt:
                words[i] = (words[i] + term) & 0xFFFFFFFF
            else:
                words[i] = (words[i] - term) & 0xFFFFFFFF

    return struct.pack(f"<{count}I", *words)


def _stage_b(data: bytes, cycles: int, decrypt: bool) -> bytes:
    words = list(struct.unpack(f"<{len(data) // 4}I", data))
    count = len(words)
    indices = range(count) if decrypt else range(count - 1, -1, -1)

    for _ in range(cycles):
        for i in indices:
            term = words[(i + 2) % count] ^ _rotate_left(words[(i + 5) % count], ROTATIONS_B[i % 4])
            if decrypt:
                words[i] = (words[i] + term) & 0xFFFFFFFF
            else:
                words[i] = (words[i] - term) & 0xFFFFFFFF

    return struct.pack(f"<{count}I", *words)


def diffuser_a_encrypt(data: bytes) -> bytes:
    return _stage_a(data, 5, False)


def diffuser_a_decrypt(data: bytes) -> bytes:
    return _stage_a(data, 5, True)


def diffuser_b_encrypt(data: bytes) -> bytes:
    return _stage_b(data, 3, False)


def diffuser_b_decrypt(data: bytes) -> bytes:
    return _stage_b(data, 3, True)


def aes_key(key: bytes, key_size: int) -> bytes:
    return key[: key_size // 8]


def diffuser_key(key: bytes, key_size: int) -> bytes:
    return key[32 : 32 + key_size // 8]


def cbc_iv(key: bytes, sector: int, key_size: int = 128, sector_size: int = 512) -> bytes:
    """Derive the sector IV used by BitLocker's EBOIV construction."""
    return AES.new(aes_key(key, key_size), AES.MODE_ECB).encrypt((sector * sector_size).to_bytes(16, "little"))


def sector_key(key: bytes, sector: int, key_size: int = 128, sector_size: int = 512) -> bytes:
    """Derive the 32-byte per-sector key used by the Elephant diffuser."""
    ecb = AES.new(diffuser_key(key, key_size), AES.MODE_ECB)
    iv = (sector * sector_size).to_bytes(16, "little")
    first = ecb.encrypt(iv)
    iv = bytearray(iv)
    iv[15] = 0x80
    return first + ecb.encrypt(bytes(iv))


def xor_repeat(data: bytes, pad: bytes) -> bytes:
    return bytes(byte ^ pad[i % len(pad)] for i, byte in enumerate(data))


def encrypt_sector(
    key: bytes,
    sector: int,
    plaintext: bytes,
    key_size: int = 128,
    sector_size: int = 512,
) -> bytes:
    """Encrypt one BitLocker AES-CBC + Elephant sector using independent components."""
    data = xor_repeat(plaintext, sector_key(key, sector, key_size, sector_size))
    data = diffuser_b_encrypt(diffuser_a_encrypt(data))
    return AES.new(
        aes_key(key, key_size),
        AES.MODE_CBC,
        iv=cbc_iv(key, sector, key_size, sector_size),
    ).encrypt(data)


def decrypt_sector(
    key: bytes,
    sector: int,
    ciphertext: bytes,
    key_size: int = 128,
    sector_size: int = 512,
) -> bytes:
    """Decrypt one BitLocker AES-CBC + Elephant sector using independent components."""
    data = AES.new(
        aes_key(key, key_size),
        AES.MODE_CBC,
        iv=cbc_iv(key, sector, key_size, sector_size),
    ).decrypt(ciphertext)
    data = diffuser_a_decrypt(diffuser_b_decrypt(data))
    return xor_repeat(data, sector_key(key, sector, key_size, sector_size))
