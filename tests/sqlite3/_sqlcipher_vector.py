from __future__ import annotations

import hashlib
import hmac

from Crypto.Cipher import AES

PAGE_SIZE = 1024
PAGE_COUNT = 4
RESERVED_SIZE = 80
SALT = bytes.fromhex("00112233445566778899aabbccddeeff")
KEY = bytes(range(32))

HMAC_ALGO = "sha1"
HMAC_DIGEST_SIZE = hashlib.new(HMAC_ALGO).digest_size
IV_SIZE = 16


def _align_for_digest() -> int:
    align = IV_SIZE + HMAC_DIGEST_SIZE
    return align if align % 16 == 0 else (align + 15) & ~15


ALIGN = _align_for_digest()
ENCRYPTED_SIZE = PAGE_SIZE - ALIGN


def _hmac_key(key: bytes, salt: bytes) -> bytes:
    hmac_salt = bytes(byte ^ 0x3A for byte in salt)
    return hashlib.pbkdf2_hmac("sha1", key, hmac_salt, 2, 32)


def plaintext_pages() -> list[bytes]:
    """Return deterministic, self-describing page content for the vector database.

    Page 1 has a valid SQLite header with a 1024-byte page size and 80 reserved bytes, matching the
    SQLCipher layout. The remaining bytes are deterministic filler so the test can compare plaintext.
    """
    body = bytearray(PAGE_SIZE)
    header = body
    header[:16] = b"SQLite format 3\x00"
    header[16:18] = PAGE_SIZE.to_bytes(2, "big")
    header[18] = 1
    header[19] = 1
    header[20] = RESERVED_SIZE
    header[21] = 64
    header[22] = 32
    header[23] = 32
    header[24:28] = (1).to_bytes(4, "big")
    header[28:32] = PAGE_COUNT.to_bytes(4, "big")
    header[40:44] = (1).to_bytes(4, "big")
    header[44:48] = (4).to_bytes(4, "big")
    header[56:60] = (1).to_bytes(4, "big")
    header[92:96] = (1).to_bytes(4, "big")
    header[96:100] = (3045000).to_bytes(4, "big")

    pages = [bytes(body)]
    for page_number in range(2, PAGE_COUNT + 1):
        page = bytearray(PAGE_SIZE)
        page[0] = 0x0D  # leaf table page
        page[1:3] = (RESERVED_SIZE << 8 | 0).to_bytes(2, "big")
        page[3:5] = (1).to_bytes(2, "big")
        page[8:12] = page_number.to_bytes(4, "big")
        page[12:16] = bytes([page_number]) * 4
        marker = f"page-{page_number}".encode()
        page[100 : 100 + len(marker)] = marker
        pages.append(bytes(page))

    return pages


def _encrypt_page(plaintext: bytes, key: bytes, hmac_key: bytes, *, page_number: int, iv: bytes) -> bytes:
    """Encrypt one page into the SQLCipher on-disk layout.

    For page 1 the first 16 bytes are the salt in place of the SQLite header magic. The remaining
    bytes up to the IV are encrypted; the IV and HMAC trailer are stored in the clear.
    """
    assert len(plaintext) == PAGE_SIZE

    if page_number == 1:
        assert plaintext.startswith(b"SQLite format 3\x00")
        header = SALT
        body = plaintext[16:ENCRYPTED_SIZE]
    else:
        header = b""
        body = plaintext[:ENCRYPTED_SIZE]

    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(body)
    digest = hmac.digest(hmac_key, ciphertext + iv + page_number.to_bytes(4, "little"), HMAC_ALGO)

    return header + ciphertext + iv + digest + b"\x00" * (PAGE_SIZE - ENCRYPTED_SIZE - IV_SIZE - HMAC_DIGEST_SIZE)


def build_vector(*, swap_pages: bool = False, tamper_page: int | None = None) -> bytes:
    """Build a short SQLCipher 2 style database using a fixed raw key and deterministic IVs.

    Read the result with ``SQLCipher2(BytesIO(data), KEY, no_kdf=True)``.
    """
    hmac_key = _hmac_key(KEY, SALT)

    pages = []
    for page_number, plaintext in enumerate(plaintext_pages(), start=1):
        iv = hashlib.sha256(f"iv-{page_number}".encode()).digest()[:IV_SIZE]
        pages.append(_encrypt_page(plaintext, KEY, hmac_key, page_number=page_number, iv=iv))

    if swap_pages:
        pages[2], pages[3] = pages[3], pages[2]

    if tamper_page is not None:
        index = tamper_page - 1
        page = bytearray(pages[index])
        body_offset = 16 if index == 0 else 0
        page[body_offset] ^= 0x01
        pages[index] = bytes(page)

    return b"".join(pages)
