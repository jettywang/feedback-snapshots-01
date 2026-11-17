from __future__ import annotations

import hashlib
import hmac
from functools import lru_cache
from pathlib import Path
from typing import BinaryIO

from dissect.database.sqlite3.encryption.sqlcipher.auth import (
    AuthenticationMode,
    AuthenticationReport,
    AuthenticationStatus,
    PageAuthentication,
)
from dissect.database.sqlite3.encryption.sqlcipher.exception import PageAuthenticationError, SQLCipherError
from dissect.database.sqlite3.exception import InvalidDatabase
from dissect.database.sqlite3.sqlite3 import SQLITE3_HEADER_MAGIC, SQLite3
from dissect.util.stream import AlignedStream

try:
    from Crypto.Cipher import AES

    HAS_CRYPTO = True

except ImportError:
    HAS_CRYPTO = False


class SQLCipher(SQLite3):
    """SQLCipher Community Edition implementation.

    Instantiate with a subclass from :class:`SQLCipher4`, :class:`SQLCipher3`, :class:`SQLCipher2`
    or :class:`SQLCipher1`.

    Decrypts a SQLCipher database from the given path or file-like oject.

    Example usage:
        >>> from dissect.database.sqlite3.encryption import AuthenticationMode, SQLCipher4
        >>> db = SQLCipher4(Path("file.db"), "passphrase", authentication=AuthenticationMode.REPORT)
        >>> row = db.table("MyTable").row(0)
        >>> db.authentication_report().all_authenticated
        True

    Args:
        fh (Path | BinaryIO): The path or file-like object to open.
        passphrase (str | bytes): String or bytes passphrase.
        salt (bytes): Optionally provide the 16-byte salt directly.
        plaintext_header_size (int): Size of plaintext header to use.
        page_size (int): Override size of each page.
        kdf_iter (int): Override amount of KDF iterations.
        kdf_algo (str | hashlib._Hash): Override KDF digest alrorithm.
        hmac_algo (str | hashlib._Hash): Override HMAC digest algorithm.
        no_kdf (bool): Disable KDF from passphrase, use as raw key.
        verify_hmac (bool): Optionally verify digest of every page. This is the legacy
            authentication switch and is equivalent to ``authentication=AuthenticationMode.STRICT``.
        authentication (AuthenticationMode | str): Explicit authentication mode. ``OFF`` preserves the
            historical behaviour, ``REPORT`` records a basis for every page read without rejecting bad
            pages, and ``STRICT`` refuses to return plaintext for pages that fail authentication.

    Raises:
        SQLCipherError: If decryption failed using the provided arguments.
        PageAuthenticationError: If a page fails authentication in ``STRICT`` mode.

    References:
        - https://www.zetetic.net/sqlcipher/design/
        - https://github.com/sqlcipher/sqlcipher
    """

    DEFAULT_PAGE_SIZE: int
    DEFAULT_KDF_ITER: int
    DEFAULT_KDF_ALGO: str
    DEFAULT_HMAC_ALGO: str | None

    # SQLCipher binds the page number into the HMAC input as a little-endian uint32 by default
    # (CIPHER_FLAG_LE_PGNO).
    PAGE_NUMBER_BINDING = "uint32-le"

    def __init__(
        self,
        fh: Path | BinaryIO,
        passphrase: str | bytes,
        *,
        salt: bytes | None = None,
        plaintext_header_size: int | None = None,
        page_size: int | None = None,
        kdf_iter: int | None = None,
        kdf_algo: str | None = None,
        hmac_algo: str | None = None,
        no_kdf: bool = False,
        verify_hmac: bool = False,
        authentication: AuthenticationMode | str = AuthenticationMode.OFF,
    ):
        if not HAS_CRYPTO:
            raise RuntimeError("Missing dependency pycryptodome")

        if isinstance(fh, Path):
            cipher_fh = fh.open("rb")
            cipher_path = fh
        else:
            cipher_fh = fh
            cipher_path = None

        self.cipher_fh = cipher_fh
        self.cipher_path = cipher_path
        self.cipher_page_size = page_size or self.DEFAULT_PAGE_SIZE
        self.kdf_iter = kdf_iter or self.DEFAULT_KDF_ITER
        self.kdf_algo = kdf_algo or self.DEFAULT_KDF_ALGO
        self.hmac_algo = hmac_algo or self.DEFAULT_HMAC_ALGO

        # The legacy verify_hmac flag keeps its meaning, but is expressed through the explicit authentication mode.
        self.authentication = AuthenticationMode(authentication)
        self._authentication_supported = bool(hmac_algo or self.DEFAULT_HMAC_ALGO)
        if verify_hmac:
            if not self._authentication_supported:
                raise ValueError("verify_hmac is set to True but no HMAC algorithm is selected")
            if self.authentication is AuthenticationMode.OFF:
                self.authentication = AuthenticationMode.STRICT
        if self.authentication is AuthenticationMode.STRICT and not self._authentication_supported:
            raise ValueError("Strict authentication requires a SQLCipher format with a page HMAC")
        self.verify_hmac = self.authentication is AuthenticationMode.STRICT
        self._page_authentication: dict[int, PageAuthentication] = {}

        if not hasattr(self.cipher_fh, "read"):
            raise ValueError("Provided file handle cannot be read from")

        if isinstance(passphrase, str):
            passphrase = passphrase.encode()

        if not passphrase:
            raise SQLCipherError("No passphrase provided")

        if isinstance(self.hmac_algo, str):
            self.hmac_algo = hashlib.new(self.hmac_algo)

        if isinstance(self.kdf_algo, str):
            self.kdf_algo = hashlib.new(self.kdf_algo)

        # Part of the header can be plaintext. We can infer that or it can be passed upon initialization.
        # https://www.zetetic.net/sqlcipher/sqlcipher-api/#cipher_plaintext_header_size
        if plaintext_header_size:
            self.plaintext_header_size = plaintext_header_size

        # The default and recommended plaintext header size is 32 bytes.
        elif (header_or_salt := self.cipher_fh.read(16)) == SQLITE3_HEADER_MAGIC:
            self.plaintext_header_size = 32
        else:
            self.plaintext_header_size = None

        if self.plaintext_header_size and not salt:
            raise SQLCipherError("Plaintext header has no salt, please provide salt manually")

        self.salt = salt or header_or_salt
        self.salt_source = "provided" if salt else "database"
        self.passphrase = passphrase

        if no_kdf:
            self.key = self.passphrase
        else:
            self.key = derive_key(
                self.passphrase, self.salt, self.kdf_iter, self.kdf_algo.name if self.kdf_algo else None
            )

        # The hmac key is derived using the raw or derived database key with it's own salt and two kdf iterations.
        # SQLCipher uses the configured KDF digest as the PBKDF2 PRF here, which can differ from the page HMAC
        # algorithm (e.g. HMAC-SHA256 pages with a PBKDF2-HMAC-SHA1 KDF).
        self.hmac_salt = bytes(i ^ 0x3A for i in self.salt)
        self.hmac_key = (
            derive_key(self.key, self.hmac_salt, 2, self.kdf_algo.name)
            if self.hmac_algo is not None and self.kdf_algo is not None
            else None
        )

        # Initialize the decrypted SQLite3 stream as a file-like object and see if that works.
        # A failure here is a decryption/format failure: even if it was triggered by an HMAC mismatch
        # (e.g. a wrong passphrase), the constructor keeps its historical error semantics.
        try:
            super().__init__(self.stream(), wal=None, checkpoint=None)
        except (InvalidDatabase, SQLCipherError) as e:
            raise SQLCipherError("Decryption of SQLCipher database failed or is not a database") from e

        # Sanity check to prevent further issues down the line.
        if self.header.page_size != self.cipher_page_size or self.header.schema_format_number not in (1, 2, 3, 4):
            raise SQLCipherError("Decryption of SQLCipher database failed or is not a database")

        # A correct SQLite header only proves that decryption produced plausible bytes. It says nothing about
        # whether the page was authenticated, so the authentication report is kept separate from this check.

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"fh={self.cipher_path or self.cipher_fh} "
            f"wal={self.wal} "
            f"checkpoint={bool(self.checkpoint)} "
            f"pages={self.page_count}>"
        )

    def close(self) -> None:
        """Close the database."""
        super().close()
        # Only close DB handle if we opened it using a path
        if self.cipher_path is not None:
            self.cipher_fh.close()

    def stream(self) -> SQLCipherStream:
        """Create a transparent decryption stream."""
        return SQLCipherStream(self)

    def authentication_report(self) -> AuthenticationReport:
        """Return the authentication results for every page that was actually read.

        The report contains only page numbers, statuses and algorithm metadata. It never contains
        the passphrase, derived keys, HMAC values or plaintext.
        """
        hmac_algorithm = self.hmac_algo.name.lower() if self.hmac_algo else None
        hmac_key_derivation = (
            f"PBKDF2-HMAC-{self.kdf_algo.name} with 2 iterations over the database key and XOR(0x3a) salt"
            if self.hmac_algo and self.kdf_algo
            else None
        )

        return AuthenticationReport(
            mode=self.authentication,
            format=self.__class__.__name__,
            hmac_algorithm=hmac_algorithm,
            hmac_key_derivation=hmac_key_derivation,
            page_number_binding=self.PAGE_NUMBER_BINDING if self.hmac_algo else "none",
            plaintext_header_size=self.plaintext_header_size or 0,
            salt_source=self.salt_source,
            pages=tuple(self._page_authentication[num] for num in sorted(self._page_authentication)),
        )

    def page_authentication(self, page_number: int) -> PageAuthentication:
        """Return the authentication result for a single page that was read.

        Args:
            page_number: The 1-based page number to look up.

        Raises:
            KeyError: If the page has not been read under an authentication-aware mode yet.
        """
        return self._page_authentication[page_number]

    def _authenticate_page(
        self,
        page_number: int,
        *,
        ciphertext: bytes,
        iv: bytes,
        page_hmac: bytes | None,
    ) -> PageAuthentication | None:
        """Authenticate a single page according to the configured authentication mode.

        Returns ``None`` in :attr:`AuthenticationMode.OFF`, otherwise the recorded result.
        The page number is bound into the HMAC input exactly as selected by this format class,
        and the plaintext header (if any) is documented as uncovered rather than assumed authenticated.
        """
        if self.authentication is AuthenticationMode.OFF:
            return None

        hmac_algorithm = self.hmac_algo.name.lower() if self.hmac_algo else None
        plaintext_header_size = (self.plaintext_header_size or 0) if page_number == 1 else 0
        common = {
            "page_number": page_number,
            "algorithm": hmac_algorithm,
            "page_number_binding": self.PAGE_NUMBER_BINDING if self.hmac_algo else "none",
            "plaintext_header_size": plaintext_header_size,
            # Page 1 always starts with the salt (or the larger plaintext header) which is excluded from the HMAC.
            "uncovered_prefix_size": plaintext_header_size or 16 if page_number == 1 else 0,
        }

        if self.hmac_algo is None or self.hmac_key is None:
            result = PageAuthentication(
                status=AuthenticationStatus.NOT_COVERED,
                detail="The SQLCipher format has no page HMAC, so decrypted content is unauthenticated.",
                **common,
            )
        else:
            page_number_bytes = self._encode_page_number(page_number)
            message = ciphertext + iv + page_number_bytes
            calculated_hmac = hmac.digest(self.hmac_key, message, self.hmac_algo.name)

            if page_hmac is not None and hmac.compare_digest(calculated_hmac, page_hmac):
                result = PageAuthentication(
                    status=AuthenticationStatus.AUTHENTICATED,
                    detail="Page HMAC matched.",
                    **common,
                )
            else:
                result = PageAuthentication(
                    status=AuthenticationStatus.FAILED,
                    detail="Page HMAC did not match.",
                    **common,
                )

        self._page_authentication[page_number] = result
        return result

    def _encode_page_number(self, page_number: int) -> bytes:
        """Encode a page number for the HMAC input according to the format's binding."""
        if self.PAGE_NUMBER_BINDING == "uint32-le":
            if not 0 <= page_number <= 0xFFFFFFFF:
                raise ValueError("Page number does not fit in a 32-bit integer")
            return page_number.to_bytes(4, "little")

        raise ValueError(f"Unsupported page number binding: {self.PAGE_NUMBER_BINDING}")


class SQLCipherStream(AlignedStream):
    """Implements a transparent decryption stream for SQLCipher databases."""

    def __init__(self, sqlcipher: SQLCipher):
        super().__init__(None, sqlcipher.cipher_page_size)

        self.fh = sqlcipher.cipher_fh
        self.sqlcipher = sqlcipher

        self._read_page = lru_cache(4096)(self._read_page)

    def _read(self, offset: int, length: int) -> bytes:
        """Calculates which pages to read from based on the given offset and length. Returns decrypted bytes."""
        start_page = offset // self.align
        num_pages = length // self.align
        return b"".join(self._read_page(num + 1) for num in range(start_page, start_page + num_pages))

    def _read_page(self, page_num: int) -> bytes:
        """Decrypt and read from the given SQLCipher page number.

        The authentication policy of the owning :class:`SQLCipher` instance applies to every read,
        whether it originates from a random access or a sequential stream read.

        References:
            - https://github.com/sqlcipher/sqlcipher-tools/blob/master/decrypt.c
        """
        if page_num < 1:
            raise ValueError("The first page number is 1")

        fh = self.sqlcipher.cipher_fh
        page_size = self.sqlcipher.cipher_page_size

        # Calculate the absolute offset in the SQLCipher file handle by multiplying the page number with
        # the SQLCipher page size.
        offset = (page_num - 1) * page_size

        # Calculate size of the page iv (always 16 bytes) plus the hmac digest size.
        hmac_algo = self.sqlcipher.hmac_algo
        digest_size = hmac_algo.digest_size if hmac_algo else 0
        align = 16 + digest_size

        # Calculate the size of the encrypted data by substracting the iv and hmac size from the page size.
        # The sum of the iv and hmac size needs to be adjusted to 16 byte blocks.
        if align % 16 != 0:
            align = (align + 15) & ~15
        enc_size = page_size - align

        # By default, the first page 'contains' the database salt (in place of SQLITE_HEAER_MAGIC) so we substract those
        # first 16 bytes from the page size and update the ciphertext offset and size accordingly.
        header_offset = 0
        header = b""
        if page_num == 1:
            header_offset = self.sqlcipher.plaintext_header_size or 16
            enc_size -= header_offset
            offset += header_offset

            # Prepare the plaintext header of the SQLite3 database if this is the first page, or read the plaintext
            # header according to the plaintext_header_size variable.
            if header_offset == 16:
                header = SQLITE3_HEADER_MAGIC
            elif header_offset:
                fh.seek(0)
                header = fh.read(header_offset)

        # The last part of the page contains the iv and optionally a hmac digest.
        fh.seek(offset + enc_size)
        iv = fh.read(16)
        page_hmac = fh.read(digest_size) if digest_size else None

        fh.seek(offset)
        ciphertext = fh.read(enc_size)

        if len(iv) != 16 or not ciphertext:
            raise EOFError

        authentication = self.sqlcipher._authenticate_page(
            page_num,
            ciphertext=ciphertext,
            iv=iv,
            page_hmac=page_hmac,
        )

        # In strict mode a page that fails its HMAC must never yield plaintext to the caller.
        if (
            authentication is not None
            and authentication.status is AuthenticationStatus.FAILED
            and self.sqlcipher.authentication is AuthenticationMode.STRICT
        ):
            raise PageAuthenticationError(page_num, authentication)

        # Decrypt the ciphertext using AES CBC and append null bytes so the plaintext aligns with the page size.
        cipher = AES.new(self.sqlcipher.key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext) + (align * b"\x00")

        # Return the plaintext prepended by the optional plaintext header.
        return header + plaintext


class SQLCipher4(SQLCipher):
    DEFAULT_PAGE_SIZE = 4096
    DEFAULT_KDF_ITER = 256_000
    DEFAULT_KDF_ALGO = "SHA512"
    DEFAULT_HMAC_ALGO = "SHA512"


class SQLCipher3(SQLCipher):
    DEFAULT_PAGE_SIZE = 1024
    DEFAULT_KDF_ITER = 64_000
    DEFAULT_KDF_ALGO = "SHA1"
    DEFAULT_HMAC_ALGO = "SHA1"


class SQLCipher2(SQLCipher):
    DEFAULT_PAGE_SIZE = 1024
    DEFAULT_KDF_ITER = 4000
    DEFAULT_KDF_ALGO = "SHA1"
    DEFAULT_HMAC_ALGO = "SHA1"


class SQLCipher1(SQLCipher):
    DEFAULT_PAGE_SIZE = 1024
    DEFAULT_KDF_ITER = 4000
    DEFAULT_KDF_ALGO = "SHA1"
    DEFAULT_HMAC_ALGO = None


def derive_key(passphrase: bytes, salt: bytes, kdf_iter: int, kdf_algo: str | None) -> bytes:
    """Derive the database key as SQLCipher would using PBKDF2."""
    if not kdf_iter or not kdf_algo:
        return passphrase

    return hashlib.pbkdf2_hmac(kdf_algo, passphrase, salt, kdf_iter, 32)
